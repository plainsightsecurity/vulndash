<?php
declare(strict_types=1);

namespace VulnDash\Lib;

/**
 * Reads and writes qualys_api_call_log - one row per physical HTTP call
 * this app makes to Qualys, written by every sync script via
 * QualysApiClient::getCallLog() (see that class for why it's the one
 * place logging every attempt, including 409 retries and every page of a
 * paginated pull). Backs the admin-only API usage page.
 *
 * api_version (added 2026-10) needs
 * database/migrations/2026-10-add-api-version-to-call-log.sql applied.
 */
class ApiCallLogRepository
{
    /**
     * Bulk-inserts a batch of call-log entries exactly as returned by
     * QualysApiClient::getCallLog() - meant to be called once per script
     * run, in a finally block, so a log is written even when the run
     * itself fails partway through. A no-op (not an error) if $calls is
     * empty, which happens whenever a run exits before making any Qualys
     * call at all (e.g. the lock was already held).
     *
     * @param array<int, array{endpoint: string, api_version: string, called_at: string, http_status: ?int, duration_sec: ?float, response_bytes: ?int, rate_limit_remaining: ?int, rate_limit_limit: ?int}> $calls
     */
    public static function recordCalls(array $calls): void
    {
        if (empty($calls)) {
            return;
        }

        $pdo = Database::getConnection();
        $stmt = $pdo->prepare('
            INSERT INTO qualys_api_call_log
                (endpoint, api_version, called_at, http_status, duration_sec, response_bytes, rate_limit_remaining, rate_limit_limit)
            VALUES
                (:endpoint, :api_version, :called_at, :http_status, :duration_sec, :response_bytes, :rate_limit_remaining, :rate_limit_limit)
        ');

        foreach ($calls as $call) {
            $stmt->execute([
                'endpoint'             => $call['endpoint'],
                'api_version'          => $call['api_version'] ?? null,
                'called_at'            => $call['called_at'],
                'http_status'          => $call['http_status'],
                'duration_sec'         => $call['duration_sec'],
                'response_bytes'       => $call['response_bytes'],
                'rate_limit_remaining' => $call['rate_limit_remaining'],
                'rate_limit_limit'     => $call['rate_limit_limit'],
            ]);
        }
    }

    /**
     * Every distinct endpoint seen in the log, oldest-call-first-seen
     * order isn't tracked - just alphabetical, since this is purely for
     * building a stable, predictable set of table columns on the admin
     * page. Empty array if nothing's been logged yet (e.g. right after
     * deploying this feature, before any sync script has run).
     *
     * @return string[]
     */
    public static function getEndpoints(): array
    {
        $pdo = Database::getConnection();
        return $pdo->query('SELECT DISTINCT endpoint FROM qualys_api_call_log ORDER BY endpoint ASC')
            ->fetchAll(\PDO::FETCH_COLUMN);
    }

    /**
     * Per-day call counts for the last $days days (including today),
     * broken down by endpoint. Shaped as one row per day, newest first,
     * each row a map of endpoint => count plus a 'total' key - ready to
     * hand straight to the admin page's table without further pivoting
     * there. A day with zero calls still gets a row (all-zero), same
     * "complete, evenly-spaced axis" reasoning as
     * VulnerabilityRepository::getVulnHistory().
     *
     * @return array<string, array<string, int>> 'Y-m-d' => [endpoint => count, ..., 'total' => count]
     */
    public static function getDailyTotals(int $days = 30): array
    {
        $pdo = Database::getConnection();
        $since = (new \DateTimeImmutable())->modify('-' . ($days - 1) . ' days')->format('Y-m-d 00:00:00');

        $stmt = $pdo->prepare('
            SELECT DATE(called_at) AS period, endpoint, COUNT(*) AS calls
            FROM qualys_api_call_log
            WHERE called_at >= :since
            GROUP BY period, endpoint
        ');
        $stmt->execute(['since' => $since]);
        $rows = $stmt->fetchAll();

        $endpoints = self::getEndpoints();
        $result = [];
        $cursor = new \DateTimeImmutable($since);
        for ($i = 0; $i < $days; $i++) {
            $key = $cursor->format('Y-m-d');
            $result[$key] = array_fill_keys($endpoints, 0) + ['total' => 0];
            $cursor = $cursor->modify('+1 day');
        }

        foreach ($rows as $row) {
            $period = $row['period'];
            if (!isset($result[$period])) {
                continue; // outside the requested window - shouldn't happen given the WHERE clause, but stay defensive
            }
            $count = (int)$row['calls'];
            $result[$period][$row['endpoint']] = $count;
            $result[$period]['total'] += $count;
        }

        return array_reverse($result, true); // newest day first, for the admin table
    }

    /**
     * Same shape as getDailyTotals(), but per hour for the last $hours
     * hours (including the current, still-in-progress hour) rather than
     * per calendar day. Worth knowing: this buckets by wall-clock hour for
     * a simple, readable table - Qualys's own rate limit is a ROLLING
     * window (e.g. "300 per rolling hour"), not aligned to the clock, so
     * this is a close approximation of load over time rather than an
     * exact reconstruction of what Qualys's own limiter saw at any given
     * moment.
     *
     * @return array<string, array<string, int>> 'Y-m-d H:00' => [endpoint => count, ..., 'total' => count]
     */
    public static function getHourlyTotals(int $hours = 24): array
    {
        $pdo = Database::getConnection();
        $since = (new \DateTimeImmutable())->modify('-' . ($hours - 1) . ' hours')->format('Y-m-d H:00:00');

        $stmt = $pdo->prepare("
            SELECT DATE_FORMAT(called_at, '%Y-%m-%d %H:00') AS period, endpoint, COUNT(*) AS calls
            FROM qualys_api_call_log
            WHERE called_at >= :since
            GROUP BY period, endpoint
        ");
        $stmt->execute(['since' => $since]);
        $rows = $stmt->fetchAll();

        $endpoints = self::getEndpoints();
        $result = [];
        $cursor = new \DateTimeImmutable($since);
        for ($i = 0; $i < $hours; $i++) {
            $key = $cursor->format('Y-m-d H:00');
            $result[$key] = array_fill_keys($endpoints, 0) + ['total' => 0];
            $cursor = $cursor->modify('+1 hour');
        }

        foreach ($rows as $row) {
            $period = $row['period'];
            if (!isset($result[$period])) {
                continue;
            }
            $count = (int)$row['calls'];
            $result[$period][$row['endpoint']] = $count;
            $result[$period]['total'] += $count;
        }

        return array_reverse($result, true); // most recent hour first
    }

    /**
     * The single most recent logged call's rate-limit snapshot, if any -
     * lets the admin page show "Qualys itself last reported N remaining
     * out of M" alongside the locally-counted totals, as a sanity check
     * that this app's own count roughly agrees with Qualys's authoritative
     * one. Null if nothing's been logged yet, or if the most recent call
     * didn't come back with rate-limit headers at all (see
     * QualysApiClient::extractRateLimitInfo()'s docblock for when that
     * happens).
     *
     * @return array{endpoint: string, called_at: string, remaining: ?int, limit: ?int}|null
     */
    public static function getLatestRateLimitSnapshot(): ?array
    {
        $pdo = Database::getConnection();
        $row = $pdo->query('
            SELECT endpoint, called_at, rate_limit_remaining, rate_limit_limit
            FROM qualys_api_call_log
            ORDER BY called_at DESC, id DESC
            LIMIT 1
        ')->fetch();

        if (!$row) {
            return null;
        }

        return [
            'endpoint'  => $row['endpoint'],
            'called_at' => $row['called_at'],
            'remaining' => $row['rate_limit_remaining'] !== null ? (int)$row['rate_limit_remaining'] : null,
            'limit'     => $row['rate_limit_limit'] !== null ? (int)$row['rate_limit_limit'] : null,
        ];
    }

    /**
     * Calls made in the last $hours hours, and what Qualys last reported as
     * left, per endpoint per API version - which is how Qualys counts its
     * limit (see QualysApiClient::budgetKeyForUrl() for the evidence), so a
     * single "N of M remaining" figure (getLatestRateLimitSnapshot()) only
     * ever describes whichever endpoint and version the last call used.
     *
     * "Calls" is a rolling window ending now, to line up with how Qualys
     * itself counts (rolling, not by calendar day). "Left" is Qualys's own
     * figure from the most recent call on that endpoint and version that
     * carried rate-limit headers - authoritative as of 'reported_at', and
     * lower now by any calls since (none, if that was the last such call).
     *
     * Every endpoint-and-version pair ever logged gets a row, even with no
     * calls in the window, so an idle one still shows its last known
     * figure. Rows logged before api_version was recorded (2026-10
     * migration) come back as one api_version = null row, only while any
     * fall inside the window.
     *
     * @return array<int, array{api_version: ?string, endpoint: ?string, calls: int, remaining: ?int, limit: ?int, reported_at: ?string}>
     *         ordered by version (2.0, 3.0, 4.0... then QPS), then endpoint,
     *         then the null row
     */
    public static function getVersionSummary(int $hours = 24): array
    {
        $pdo = Database::getConnection();
        $since = (new \DateTimeImmutable())->modify("-{$hours} hours")->format('Y-m-d H:i:s');

        $stmt = $pdo->prepare('
            SELECT api_version, endpoint, COUNT(*) AS calls
            FROM qualys_api_call_log
            WHERE called_at >= :since
            GROUP BY api_version, endpoint
        ');
        $stmt->execute(['since' => $since]);
        $callsByPair = [];
        $unrecordedCalls = 0;
        foreach ($stmt->fetchAll() as $row) {
            if ($row['api_version'] === null) {
                $unrecordedCalls += (int)$row['calls'];
            } else {
                $callsByPair[$row['api_version'] . '|' . $row['endpoint']] = (int)$row['calls'];
            }
        }

        $pairs = $pdo->query('
            SELECT DISTINCT api_version, endpoint
            FROM qualys_api_call_log
            WHERE api_version IS NOT NULL
        ')->fetchAll();
        usort($pairs, static function (array $a, array $b): int {
            if ($a['api_version'] !== $b['api_version']) {
                // QPS after every numbered version.
                if ($a['api_version'] === 'QPS' || $b['api_version'] === 'QPS') {
                    return ($a['api_version'] === 'QPS') <=> ($b['api_version'] === 'QPS');
                }
                return version_compare($a['api_version'], $b['api_version']);
            }
            return strcmp($a['endpoint'], $b['endpoint']);
        });

        $snapshotStmt = $pdo->prepare('
            SELECT rate_limit_remaining, rate_limit_limit, called_at
            FROM qualys_api_call_log
            WHERE api_version = :version AND endpoint = :endpoint AND rate_limit_remaining IS NOT NULL
            ORDER BY called_at DESC, id DESC
            LIMIT 1
        ');

        $summary = [];
        foreach ($pairs as $pair) {
            $snapshotStmt->execute(['version' => $pair['api_version'], 'endpoint' => $pair['endpoint']]);
            $snapshot = $snapshotStmt->fetch() ?: null;
            $summary[] = [
                'api_version' => $pair['api_version'],
                'endpoint'    => $pair['endpoint'],
                'calls'       => $callsByPair[$pair['api_version'] . '|' . $pair['endpoint']] ?? 0,
                'remaining'   => $snapshot !== null ? (int)$snapshot['rate_limit_remaining'] : null,
                'limit'       => $snapshot !== null && $snapshot['rate_limit_limit'] !== null ? (int)$snapshot['rate_limit_limit'] : null,
                'reported_at' => $snapshot['called_at'] ?? null,
            ];
        }

        if ($unrecordedCalls > 0) {
            $summary[] = [
                'api_version' => null,
                'endpoint'    => null,
                'calls'       => $unrecordedCalls,
                'remaining'   => null,
                'limit'       => null,
                'reported_at' => null,
            ];
        }

        return $summary;
    }
}
