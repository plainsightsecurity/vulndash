<?php
declare(strict_types=1);

namespace VulnDash\Lib;

/**
 * Reads sync_log for the "last sync" status strip shown on the dashboard -
 * purely informational, no writes. Both cron jobs
 * (scripts/sync_knowledge_base.php and scripts/sync_host_detections.php)
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
     *     Qualys didn't return a QID the daily fetch job asked for, or one
     *     has waited past kb_missing_warn_hours. Waiting for the next daily
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
            ];
        }

        return $results;
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
