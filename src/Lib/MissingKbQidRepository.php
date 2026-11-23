<?php
declare(strict_types=1);

namespace VulnDash\Lib;

/**
 * QIDs that Qualys reported on a host but that aren't in the local
 * knowledge_base, so their detections were skipped (HostSyncWriter::
 * upsertDetections() can't score a detection without its KB row).
 *
 * WHY THIS EXISTS. That skip used to be silent. A missing QID doesn't just
 * leave a hole in the KB cache - it hides a real finding from the client's
 * dashboard, with nothing recorded anywhere. Most skips are harmless and
 * short-lived: a brand-new QID can reach a host's detections before the
 * next KB sync has fetched it, and clears on its own. One that outlives a
 * couple of KB syncs is a real gap - the KB sweep missed it.
 *
 * Kept in sync_state ('kb_missing_qids') as qid => first/last seen and host
 * count, updated by both host jobs, plus fetch attempts by the daily
 * scripts/fetch_missing_kb_qids.php, which asks Qualys for every QID on the
 * list by id so nobody has to act on it by hand. A QID leaves the list only once it is
 * in knowledge_base - NOT because a run didn't see it: the hourly pull is
 * incremental, so a host carrying the QID may simply not have been
 * re-pulled that hour, and dropping it then would make the list flap.
 */
final class MissingKbQidRepository
{
    private const STATE_KEY = 'kb_missing_qids';

    /**
     * Default for sync.kb_missing_warn_hours. Past this, a QID the daily
     * fetch job has not yet tried means the job isn't running: a day and a
     * half covers the longest normal wait (first seen just after the
     * day's run) with margin. A QID the job asked for and Qualys didn't
     * return needs a person whatever its age - see needsAttention().
     */
    public const DEFAULT_WARN_HOURS = 36;

    /** Bounds the state row (sync_state.state_json is TEXT); oldest-seen kept first. */
    private const MAX_TRACKED = 500;

    /**
     * Merges one run's skipped QIDs into the stored list, drops any now in
     * knowledge_base, and returns what's still outstanding (oldest first).
     * Row-locked, since the hourly sync and the reconcile can overlap.
     *
     * @param array<int, int> $skipped qid => number of hosts it was skipped on this run
     * @return array<int, array{qid: int, first_seen: string, last_seen: string, hosts: int}>
     */
    public static function record(\PDO $pdo, array $skipped): array
    {
        $now = date('Y-m-d H:i:s');
        $pdo->beginTransaction();
        try {
            $pdo->prepare('INSERT IGNORE INTO sync_state (sync_type, state_json) VALUES (:type, :state)')
                ->execute(['type' => self::STATE_KEY, 'state' => '{}']);
            $stmt = $pdo->prepare('SELECT state_json FROM sync_state WHERE sync_type = :type FOR UPDATE');
            $stmt->execute(['type' => self::STATE_KEY]);
            $state = json_decode((string)$stmt->fetchColumn(), true);
            $state = is_array($state) ? $state : [];

            foreach ($skipped as $qid => $hosts) {
                $key = (string)(int)$qid;
                // array_merge keeps the fetch-attempt fields markFetchAttempt() set.
                $state[$key] = array_merge($state[$key] ?? [], [
                    'first_seen' => $state[$key]['first_seen'] ?? $now,
                    'last_seen'  => $now,
                    'hosts'      => (int)$hosts,
                ]);
            }

            $state = self::withoutResolved($pdo, $state);
            uasort($state, static fn(array $a, array $b): int => strcmp($a['first_seen'], $b['first_seen']));
            $state = array_slice($state, 0, self::MAX_TRACKED, true);

            $pdo->prepare('UPDATE sync_state SET state_json = :state WHERE sync_type = :type')
                ->execute(['state' => json_encode($state === [] ? new \stdClass() : $state), 'type' => self::STATE_KEY]);
            $pdo->commit();
        } catch (\Throwable $e) {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
            throw $e;
        }

        return self::toList($state);
    }

    /**
     * Read-only view for the dashboard: the stored list, less anything that
     * has reached knowledge_base since the last host run (e.g. via
     * diagnose_kb.php --fix or a KB sync), oldest first.
     *
     * @return array<int, array{qid: int, first_seen: string, last_seen: string, hosts: int}>
     */
    public static function outstanding(): array
    {
        $pdo = Database::getConnection();
        $stmt = $pdo->prepare('SELECT state_json FROM sync_state WHERE sync_type = :type');
        $stmt->execute(['type' => self::STATE_KEY]);
        $state = json_decode((string)$stmt->fetchColumn(), true);
        if (!is_array($state) || $state === []) {
            return [];
        }
        $state = self::withoutResolved($pdo, $state);
        uasort($state, static fn(array $a, array $b): int => strcmp($a['first_seen'], $b['first_seen']));
        return self::toList($state);
    }

    /**
     * Records that the daily fetch job asked Qualys for these QIDs and they
     * didn't come back - so the panel can say Qualys isn't returning them,
     * which no amount of waiting fixes.
     *
     * @param int[] $qids
     */
    public static function markFetchAttempt(\PDO $pdo, array $qids, string $result): void
    {
        if ($qids === []) {
            return;
        }
        $now = date('Y-m-d H:i:s');
        $pdo->beginTransaction();
        try {
            $stmt = $pdo->prepare('SELECT state_json FROM sync_state WHERE sync_type = :type FOR UPDATE');
            $stmt->execute(['type' => self::STATE_KEY]);
            $state = json_decode((string)$stmt->fetchColumn(), true);
            $state = is_array($state) ? $state : [];
            foreach ($qids as $qid) {
                $key = (string)(int)$qid;
                if (!isset($state[$key])) {
                    continue;
                }
                $state[$key]['fetch_attempts'] = (int)($state[$key]['fetch_attempts'] ?? 0) + 1;
                $state[$key]['last_fetch_at'] = $now;
                $state[$key]['last_fetch_result'] = $result;
            }
            $pdo->prepare('UPDATE sync_state SET state_json = :state WHERE sync_type = :type')
                ->execute(['state' => json_encode($state === [] ? new \stdClass() : $state), 'type' => self::STATE_KEY]);
            $pdo->commit();
        } catch (\Throwable $e) {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
            throw $e;
        }
    }

    /**
     * Whether the list needs a person: Qualys didn't return a QID the daily
     * job asked for, or one has waited past warnHours() (the job isn't
     * running). A QID simply waiting for its first daily fetch doesn't.
     *
     * @param array<int, array{qid: int, first_seen: string, fetch_attempts: int}> $outstanding
     */
    public static function needsAttention(array $outstanding): bool
    {
        $cutoff = time() - self::warnHours() * 3600;
        foreach ($outstanding as $row) {
            if ($row['fetch_attempts'] > 0 || strtotime($row['first_seen']) < $cutoff) {
                return true;
            }
        }
        return false;
    }

    /** sync.kb_missing_warn_hours, or the default - see DEFAULT_WARN_HOURS. */
    public static function warnHours(): int
    {
        $value = Config::get('sync.kb_missing_warn_hours');
        return max(1, $value !== null ? (int)$value : self::DEFAULT_WARN_HOURS);
    }

    /**
     * @param array<string, array{first_seen: string, last_seen: string, hosts: int}> $state
     * @return array<string, array{first_seen: string, last_seen: string, hosts: int}>
     */
    private static function withoutResolved(\PDO $pdo, array $state): array
    {
        if ($state === []) {
            return [];
        }
        $qids = array_map('intval', array_keys($state));
        $in = implode(',', array_fill(0, count($qids), '?'));
        $stmt = $pdo->prepare('SELECT qid FROM knowledge_base WHERE qid IN (' . $in . ')');
        $stmt->execute($qids);
        foreach ($stmt->fetchAll(\PDO::FETCH_COLUMN) as $present) {
            unset($state[(string)(int)$present]);
        }
        return $state;
    }

    /**
     * @param array<string, array{first_seen: string, last_seen: string, hosts: int}> $state
     * @return array<int, array{qid: int, first_seen: string, last_seen: string, hosts: int, fetch_attempts: int, last_fetch_at: ?string, last_fetch_result: ?string}>
     */
    private static function toList(array $state): array
    {
        $out = [];
        foreach ($state as $qid => $row) {
            $out[] = [
                'qid'               => (int)$qid,
                'first_seen'        => (string)$row['first_seen'],
                'last_seen'         => (string)$row['last_seen'],
                'hosts'             => (int)$row['hosts'],
                'fetch_attempts'    => (int)($row['fetch_attempts'] ?? 0),
                'last_fetch_at'     => isset($row['last_fetch_at']) ? (string)$row['last_fetch_at'] : null,
                'last_fetch_result' => isset($row['last_fetch_result']) ? (string)$row['last_fetch_result'] : null,
            ];
        }
        return $out;
    }

    /**
     * One line for a job's log, ending with the command that fetches the
     * outstanding QIDs now. Shared so both host jobs report it identically.
     *
     * @param array<int, int> $skipped this run's qid => hosts
     * @param array<int, array{qid: int, first_seen: string, last_seen: string, hosts: int}> $outstanding
     */
    public static function logLine(array $skipped, array $outstanding): string
    {
        if ($skipped === [] && $outstanding === []) {
            return "KnowledgeBase coverage: every QID reported this run is in the local KB.\n";
        }
        $parts = [];
        foreach (array_slice($skipped, 0, 10, true) as $qid => $hosts) {
            $parts[] = "{$qid} ({$hosts} host" . ($hosts === 1 ? '' : 's') . ')';
        }
        $line = 'KnowledgeBase coverage: ' . count($skipped) . ' QID(s) reported this run are NOT in the local KB, so their detections were skipped'
            . ($parts !== [] ? ': ' . implode(', ', $parts) . (count($skipped) > 10 ? ', ...' : '') : '') . ".\n";
        if ($outstanding !== []) {
            $line .= '  Outstanding: ' . count($outstanding) . ' QID(s), oldest first seen ' . $outstanding[0]['first_seen']
                . '. scripts/fetch_missing_kb_qids.php fetches them on its daily run; to fetch now: php scripts/diagnose_kb.php --qid='
                . implode(',', array_slice(array_column($outstanding, 'qid'), 0, 50)) . " --fix\n";
        }
        return $line;
    }
}
