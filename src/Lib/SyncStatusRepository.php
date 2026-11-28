<?php
declare(strict_types=1);

namespace VulnDash\Lib;

/**
 * Reads sync_log for the "last sync" status strip shown on the dashboard -
 * purely informational, no writes. The cron jobs
 * (scripts/sync_knowledge_base.php, scripts/sync_host_detections.php and,
 * since 2026-11-27, scripts/sync_exploit_intel.php)
 * already write a sync_log row on every run regardless of outcome; this
 * just summarises the most recent state per sync_type so a stuck or
 * silently-failing cron job is visible on the page itself, rather than
 * requiring someone to go looking through log files, crontab, or syslog to
 * notice - see the July 2026 incident where cron had been failing at the
 * shell redirect (before PHP ever started, so nothing reached sync_log at
 * all) for an unknown period, discovered only by chance.
 *
 * That specific failure mode - the whole process never starting - can't be
 * caught by anything reading sync_log, by definition: if cron never
 * invokes the script, no row is ever written either way. What this DOES
 * catch is the far more common downstream symptom: too much time having
 * passed since the last successful row, which is what actually happened
 * in that incident and is what an admin actually wants to know at a
 * glance ("is my data current?"), regardless of the underlying cause.
 */
class SyncStatusRepository
{
    /** @var array<string, string> sync_type => display label */
    private const LABELS = [
        'knowledge_base'  => 'Knowledge Base sync',
        'host_detections' => 'Host detection sync',
        'exploit_intel'   => 'Exploit intel sync (CISA KEV + EPSS)',
    ];

    /**
     * The exploit-intel sync's two feeds, by the table each replaces in full
     * when it succeeds (every row's synced_at is reset then). A run where only
     * one feed fails still records 'success' - by design, so one outage
     * doesn't stale the other - so the card checks each feed's own freshness
     * and turns amber ('warning') if one hasn't refreshed within the overdue
     * threshold (2026-11-27).
     */
    private const EXPLOIT_FEEDS = [
        'cisa_kev'    => 'CISA KEV feed',
        'epss_scores' => 'EPSS feed',
    ];

    /**
     * Expected cadence per sync type, in minutes - used only to flag a
     * sync as "overdue" in the UI, not for anything functional. These are
     * config-overridable (sync.knowledge_base_expected_interval_minutes /
     * sync.host_detections_expected_interval_minutes in
     * src/config/config.php - the key is built from the sync_type, see
     * getSyncStatuses()) because the actual crontab schedule lives
     * outside this app entirely and this can't introspect it - the
     * defaults below match the real crontab as of 2026-10-17, when it was
     * throttled to fit the licence's 25 calls per API version per 24h: KB
     * sync once a day at 02:00, host detections every 3 hours at :18. With
     * the 2x slack multiplier below, that flags the KB sync overdue after
     * ~48 hours without a success and host detections after ~6 hours.
     * Update the config value (or here, if you'd rather not touch
     * config.php) if the crontab ever changes again.
     */
    private const DEFAULT_EXPECTED_INTERVAL_MINUTES = [
        'knowledge_base'  => 1440,
        'host_detections' => 180,
        'exploit_intel'   => 360,   // 00:30, 06:30, 12:30, 18:30
    ];

    /**
     * How much slack over the expected interval before flagging "overdue"
     * - cron jitter, a slow run, or the overlapping-run lock skipping one
     * cycle shouldn't trip this on their own.
     */
    private const OVERDUE_MULTIPLIER = 2;

    /**
     * @return array<int, array{
     *     sync_type: string, label: string, state: string,
     *     last_status: ?string, last_started_at: ?string,
     *     last_completed_at: ?string, last_error_message: ?string,
     *     records_processed: ?int, last_success_at: ?string,
     *     missing_kb_qids: array<int, array{qid: int, first_seen: string, last_seen: string, hosts: int}>,
     *     kb_missing_warn_hours: int
     * }> one row per known sync_type, in the order defined above.
     *     missing_kb_qids is only ever filled for host_detections: QIDs whose
     *     detections were skipped for having no local KB row (see
     *     MissingKbQidRepository). A healthy sync becomes 'warning' only when
     *     the list needs a person (MissingKbQidRepository::needsAttention()):
     *     Qualys didn't return a QID the missing-QID fetch job asked for, or one
     *     has waited past kb_missing_warn_hours. Waiting for the next 6-hourly
     *     fetch is normal and stays healthy.
     */
    public static function getSyncStatuses(): array
    {
        $pdo = Database::getConnection();
        $results = [];

        foreach (self::LABELS as $syncType => $label) {
            $stmt = $pdo->prepare('
                SELECT status, started_at, completed_at, records_processed, error_message
                FROM sync_log
                WHERE sync_type = :type
                ORDER BY started_at DESC
                LIMIT 1
            ');
            $stmt->execute(['type' => $syncType]);
            $latest = $stmt->fetch();
            $latest = $latest ?: null;

            $stmt = $pdo->prepare("
                SELECT completed_at
                FROM sync_log
                WHERE sync_type = :type AND status = 'success' AND completed_at IS NOT NULL
                ORDER BY completed_at DESC
                LIMIT 1
            ");
            $stmt->execute(['type' => $syncType]);
            $lastSuccessAt = $stmt->fetchColumn();
            $lastSuccessAt = $lastSuccessAt !== false ? $lastSuccessAt : null;

            $expectedMinutes = (int)(Config::get("sync.{$syncType}_expected_interval_minutes")
                ?? self::DEFAULT_EXPECTED_INTERVAL_MINUTES[$syncType]);
            // When the host sync's auto interval has slowed it down to fit
            // the API budget, that's the cadence to judge "overdue" by.
            if ($syncType === 'host_detections') {
                $expectedMinutes = max($expectedMinutes, (int)(ApiBudget::autoState()['interval'] ?? 0));
            }

            $state = self::deriveState($latest, $lastSuccessAt, $expectedMinutes);

            $missingKbQids = [];
            $warnHours = MissingKbQidRepository::warnHours();
            if ($syncType === 'host_detections') {
                $missingKbQids = MissingKbQidRepository::outstanding();
                if ($state === 'healthy' && MissingKbQidRepository::needsAttention($missingKbQids)) {
                    $state = 'warning';
                }
            }

            $staleFeeds = [];
            if ($syncType === 'exploit_intel' && $state === 'healthy') {
                $limit = time() - $expectedMinutes * 60 * self::OVERDUE_MULTIPLIER;
                foreach (self::EXPLOIT_FEEDS as $table => $feedLabel) {
                    $last = $pdo->query("SELECT MAX(synced_at) FROM {$table}")->fetchColumn();
                    $last = $last !== false && $last !== null ? (string)$last : null;
                    if ($last === null || strtotime($last) < $limit) {
                        $staleFeeds[] = ['feed' => $feedLabel, 'last' => $last];
                    }
                }
                if ($staleFeeds !== []) {
                    $state = 'warning';
                }
            }

            $results[] = [
                'sync_type'          => $syncType,
                'label'              => $label,
                'state'              => $state,
                'last_status'        => $latest['status'] ?? null,
                'last_started_at'    => $latest['started_at'] ?? null,
                'last_completed_at'  => $latest['completed_at'] ?? null,
                'last_error_message' => $latest['error_message'] ?? null,
                'records_processed'  => $latest['records_processed'] ?? null,
                'last_success_at'    => $lastSuccessAt,
                'missing_kb_qids'    => $missingKbQids,
                'kb_missing_warn_hours' => $warnHours,
                'stale_feeds'        => $staleFeeds,
                'notes'              => [],
                'is_backup'          => false,
            ];
        }

        foreach (self::backupStatuses() as $row) {
            $results[] = $row;
        }

        return $results;
    }

    /** sync_type => [label, status file section, default expected minutes, config key] */
    private const BACKUP_CARDS = [
        'backup'       => ['Nightly backup (restic)', 'backup', 1440, 'sync.backup_expected_interval_minutes'],
        'backup_check' => ['Weekly backup check', 'check', 10080, 'sync.backup_check_expected_interval_minutes'],
    ];

    public const DEFAULT_BACKUP_STATUS_FILE = '/var/lib/plainsight-backup/status.json';

    /**
     * The nightly restic backup and the weekly backup check (2026-11-27).
     * They run as root from systemd timers, outside this app (scripts in
     * config/backup/), and each writes its result to a small JSON status
     * file (backup.status_file, default /var/lib/plainsight-backup/status.json,
     * readable by www-data, no credentials in it). Read here in the same
     * shape as the sync cards, so the dashboard panel and SyncHealthAlerts
     * cover them with no extra code: failed, stuck (said "running" for over
     * a day), overdue (no success in twice the expected interval: 48 hours
     * for the backup, 14 days for the check) and warning (the backup's 5%
     * spot-check or the check's restore test reported something short of a
     * failure). No file yet (scripts not installed) shows as "never run",
     * which never alerts.
     *
     * @return array<int, array<string, mixed>>
     */
    public static function backupStatuses(): array
    {
        // PLAINSIGHT_BACKUP_STATUS is the same override plainsight-backup-status
        // honours (used by the tests); otherwise config, then the default.
        $file = (string)(getenv('PLAINSIGHT_BACKUP_STATUS') ?: (Config::get('backup.status_file') ?? self::DEFAULT_BACKUP_STATUS_FILE));
        $data = is_readable($file) ? json_decode((string)@file_get_contents($file), true) : null;
        $data = is_array($data) ? $data : [];
        $local = static function ($iso): ?string {
            $ts = is_string($iso) && $iso !== '' ? strtotime($iso) : false;
            return $ts !== false ? date('Y-m-d H:i:s', $ts) : null;
        };

        $rows = [];
        foreach (self::BACKUP_CARDS as $type => [$label, $section, $defaultMinutes, $configKey]) {
            $d = is_array($data[$section] ?? null) ? $data[$section] : null;
            $expected = (int)(Config::get($configKey) ?? $defaultMinutes);
            $status = (string)($d['status'] ?? '');
            $lastRun = $local($d['last_run'] ?? null);
            $lastSuccess = $local($d['last_success'] ?? null);
            $message = trim((string)($d['message'] ?? ''));

            if ($d === null) {
                $state = 'never_run';
                $message = $data === [] && !is_file($file)
                    ? 'No status recorded yet - install the backup scripts from config/backup/ (see the README).'
                    : $message;
            } elseif ($status === 'running') {
                $state = $lastRun !== null && time() - strtotime($lastRun) > 86400 ? 'stuck' : 'running';
            } elseif ($status === 'failed') {
                $state = 'failed';
            } elseif ($lastSuccess === null) {
                $state = 'never_run';
            } elseif (time() - strtotime($lastSuccess) > $expected * 60 * self::OVERDUE_MULTIPLIER) {
                $state = 'overdue';
            } elseif ($status === 'warning') {
                $state = 'warning';
            } else {
                $state = 'healthy';
            }

            $rows[] = [
                'sync_type'          => $type,
                'label'              => $label,
                'state'              => $state,
                'last_status'        => $status !== '' ? $status : null,
                'last_started_at'    => $lastRun,
                'last_completed_at'  => null,
                'last_error_message' => $state === 'failed' ? $message : null,
                'records_processed'  => null,
                'last_success_at'    => $lastSuccess,
                'missing_kb_qids'    => [],
                'kb_missing_warn_hours' => MissingKbQidRepository::warnHours(),
                'stale_feeds'        => [],
                // Shown under the card (and used for a warning email); a
                // failure's message is already the card's main text.
                'notes'              => $state !== 'failed' && $message !== '' ? [$message] : [],
                'is_backup'          => true,
            ];
        }
        return $rows;
    }

    /**
     * @param array{status: string, started_at: string, completed_at: ?string, records_processed: int, error_message: ?string}|null $latest
     *
     * @return string one of: never_run, running, stuck, failed, overdue, healthy
     */
    private static function deriveState(?array $latest, ?string $lastSuccessAt, int $expectedMinutes): string
    {
        if ($latest === null) {
            return 'never_run';
        }

        $staleThresholdSeconds = $expectedMinutes * 60 * self::OVERDUE_MULTIPLIER;

        if ($latest['status'] === 'running') {
            $runningForSeconds = time() - strtotime($latest['started_at']);
            // Still within a normal run's expected duration - genuinely
            // in progress, not stuck.
            return $runningForSeconds > $staleThresholdSeconds ? 'stuck' : 'running';
        }

        if ($latest['status'] === 'failed') {
            return 'failed';
        }

        // Latest attempt succeeded - but is that success recent enough?
        if ($lastSuccessAt === null) {
            // Shouldn't happen if the latest row's own status is
            // 'success', but defensive in case of a data inconsistency.
            return 'never_run';
        }

        $secondsSinceSuccess = time() - strtotime($lastSuccessAt);
        return $secondsSinceSuccess > $staleThresholdSeconds ? 'overdue' : 'healthy';
    }
}
