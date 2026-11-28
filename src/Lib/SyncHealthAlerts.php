<?php
declare(strict_types=1);

namespace VulnDash\Lib;

/**
 * Emails admins when the Knowledge Base, host detection or exploit intel
 * (CISA KEV + EPSS, since 2026-11-27) sync goes wrong - or the nightly
 * backup or weekly backup check (SyncStatusRepository::backupStatuses()) -
 * and again when it recovers (2026-11-27). Run every 15 minutes by
 * scripts/send_sync_alerts.php. It judges health exactly as the dashboard's
 * sync status panel does (SyncStatusRepository::getSyncStatuses()), so an
 * email and the panel can never disagree:
 *
 *   - failed:  the latest run failed. Sent only once the sync has been
 *              unhealthy for alerts.sync_failed_grace_minutes (default 60),
 *              so one transient Qualys error that the next run recovers
 *              from never emails anyone.
 *   - stuck:   a run has said "running" for longer than twice the expected
 *              interval - a crashed process or a lock left behind.
 *   - overdue: no success for twice the expected interval
 *              (sync.<type>_expected_interval_minutes). Also what a cron job
 *              that has stopped running looks like.
 *   - warning: missing knowledge base QIDs that need a person (see
 *              MissingKbQidRepository::needsAttention()), or one exploit
 *              intel feed not refreshed in twice its interval while the
 *              runs still succeed on the other.
 *
 * stuck, overdue and warning are already time-based, so they're sent the
 * first time they're seen. "running" and "never run" are neutral - they
 * neither raise nor clear an alert - so a sync that fails, starts its next
 * run and fails again counts as one continuous problem.
 *
 * Each problem is emailed once, then again if it changes (e.g. failed ->
 * stuck) and as a reminder every alerts.sync_reminder_hours (default 24;
 * 0 = never) while it lasts. Once a problem that was emailed clears, one
 * "back to normal" email follows. Everything found in one run goes in one
 * email. State in sync_state 'sync_health_alerts'. Recipients are the same
 * as the API budget alerts (alerts.admin_emails, else every active admin).
 * alerts.sync_health => false turns it all off.
 *
 * What this can't see: if cron itself stops, this job stops with it.
 */
final class SyncHealthAlerts
{
    public const DEFAULT_FAILED_GRACE_MINUTES = 60;
    public const DEFAULT_REMINDER_HOURS = 24;

    private const PROBLEM_STATES = ['failed', 'stuck', 'overdue', 'warning'];
    private const NEUTRAL_STATES = ['running', 'never_run'];
    private const ERROR_MAX_CHARS = 300;

    /**
     * @param bool $dryRun work out and return what would be sent, but send
     *                     nothing and leave the saved state alone
     * @return array{problems: string[], recoveries: string[], sent_to: string[]}
     */
    public static function check(?int $now = null, bool $dryRun = false): array
    {
        $now ??= time();
        $result = ['problems' => [], 'recoveries' => [], 'sent_to' => []];
        if (Config::get('alerts.sync_health') === false) {
            return $result;
        }

        $graceSeconds    = max(0, (int)(Config::get('alerts.sync_failed_grace_minutes') ?? self::DEFAULT_FAILED_GRACE_MINUTES)) * 60;
        $reminderSeconds = max(0, (int)(Config::get('alerts.sync_reminder_hours') ?? self::DEFAULT_REMINDER_HOURS)) * 3600;

        $pdo = Database::getConnection();
        $stmt = $pdo->prepare("SELECT state_json FROM sync_state WHERE sync_type = 'sync_health_alerts'");
        $stmt->execute();
        $saved = json_decode((string)$stmt->fetchColumn(), true);
        $saved = is_array($saved) ? $saved : [];
        $before = $saved;
        $reported = [];   // sync types with a line in this run's email

        foreach (SyncStatusRepository::getSyncStatuses() as $s) {
            $type  = $s['sync_type'];
            $state = $s['state'];
            $prev  = $saved[$type] ?? null;

            if (in_array($state, self::NEUTRAL_STATES, true)) {
                continue;
            }

            if (!in_array($state, self::PROBLEM_STATES, true)) {
                // Healthy. Say so only if we'd told someone it wasn't.
                if ($prev !== null && !empty($prev['alerted'])) {
                    $result['recoveries'][] = "{$s['label']} is working again"
                        . ($s['last_success_at'] !== null ? ' (last success ' . self::when($s['last_success_at']) . ').' : '.');
                    $reported[] = $type;
                }
                unset($saved[$type]);
                continue;
            }

            if ($prev === null) {
                $prev = ['state' => $state, 'since' => $now, 'alerted' => false, 'last_sent' => 0];
            }
            $changed = $prev['state'] !== $state;
            $prev['state'] = $state;

            $grace = $state === 'failed' ? $graceSeconds : 0;
            $send = false;
            $prefix = '';
            if (empty($prev['alerted'])) {
                $send = $now - (int)$prev['since'] >= $grace;
            } elseif ($changed) {
                $send = true;
            } elseif ($reminderSeconds > 0 && $now - (int)$prev['last_sent'] >= $reminderSeconds) {
                $send = true;
                $prefix = 'Still not fixed: ';
            }

            if ($send) {
                $result['problems'][] = $prefix . self::describe($s);
                $prev['alerted'] = true;
                $prev['last_sent'] = $now;
                $reported[] = $type;
            }
            $saved[$type] = $prev;
        }

        if ($dryRun) {
            return $result;
        }
        if ($result['problems'] === [] && $result['recoveries'] === []) {
            self::save($saved, $before);
            return $result;
        }

        $appName = (string)(Config::get('app.name') ?? 'VulnDash');
        if ($result['problems'] !== []) {
            $topic = 'sync problem';
            $intro = null;   // "<app> needs your attention:"
            $lines = array_merge($result['problems'], $result['recoveries']);
        } else {
            $topic = 'syncs back to normal';
            $intro = "{$appName}'s syncs are back to normal:";
            $lines = $result['recoveries'];
        }
        $footer = 'You get this because you are an admin. You will hear again if the problem changes'
            . ($reminderSeconds > 0 ? ', every ' . intdiv($reminderSeconds, 3600) . ' hours while it lasts,' : '')
            . ' and once it is fixed.';
        $url = rtrim((string)(Config::get('app.base_url') ?? ''), '/') . '/dashboard';

        foreach (ApiBudgetAlerts::recipients() as $email => $name) {
            if (Mailer::sendAdminAlertEmail($email, $name, $topic, $lines, $url, 'Open the dashboard', $intro, $footer)) {
                $result['sent_to'][] = $email;
            }
        }

        // Nobody got it (no recipients, or Resend refused): keep the problem
        // tracked but un-sent, and any recovery still pending, so the next
        // run tries again instead of the alert being lost.
        if ($result['sent_to'] === []) {
            foreach (array_unique($reported) as $type) {
                if (!isset($before[$type])) {
                    $saved[$type]['alerted'] = false;
                    $saved[$type]['last_sent'] = 0;
                } elseif (!isset($saved[$type])) {
                    $saved[$type] = $before[$type];
                } else {
                    $saved[$type]['state'] = $before[$type]['state'];
                    $saved[$type]['alerted'] = $before[$type]['alerted'];
                    $saved[$type]['last_sent'] = $before[$type]['last_sent'];
                }
            }
        }
        self::save($saved, $before);
        return $result;
    }

    /** @param array<string, mixed> $saved @param array<string, mixed> $before */
    private static function save(array $saved, array $before): void
    {
        if ($saved === $before) {
            return;
        }
        Database::getConnection()->prepare("
            INSERT INTO sync_state (sync_type, state_json) VALUES ('sync_health_alerts', :state) AS new
            ON DUPLICATE KEY UPDATE state_json = new.state_json
        ")->execute(['state' => json_encode($saved)]);
    }

    /** @param array<string, mixed> $s one row of SyncStatusRepository::getSyncStatuses() */
    private static function describe(array $s): string
    {
        $label = $s['label'];
        $lastOk = $s['last_success_at'] !== null
            ? ' Last success: ' . self::when($s['last_success_at']) . '.'
            : ' It has never succeeded.';

        switch ($s['state']) {
            case 'failed':
                $at = $s['last_completed_at'] ?? $s['last_started_at'];
                $err = trim((string)($s['last_error_message'] ?? ''));
                if (mb_strlen($err) > self::ERROR_MAX_CHARS) {
                    $err = mb_substr($err, 0, self::ERROR_MAX_CHARS) . '...';
                }
                return "{$label} failed" . ($at !== null ? ' at ' . self::when($at) : '')
                    . ($err !== '' ? ': ' . rtrim($err, '.') . '.' : '.') . $lastOk;
            case 'stuck':
                return "{$label} has said \"running\" since " . self::when((string)$s['last_started_at'])
                    . ', far longer than a run takes - the process probably died or left its lock behind.' . $lastOk;
            case 'overdue':
                return "{$label} hasn't succeeded for longer than expected." . $lastOk
                    . (!empty($s['is_backup'])
                        ? ' Nothing has failed since, so check its systemd timer is still running (systemctl list-timers \'plainsight-backup*\').'
                        : ' Nothing has failed since, so check cron is still running the job.');
            case 'warning':
                if (!empty($s['notes'])) {
                    return "{$label}: " . implode(' ', $s['notes']);
                }
                if (!empty($s['stale_feeds'])) {
                    return "{$label}: " . implode('; ', array_map(
                        static fn (array $f): string => $f['feed'] . ($f['last'] !== null ? ' last refreshed ' . self::when($f['last']) : ' has never loaded'),
                        $s['stale_feeds']
                    )) . '. Runs still succeed on the other feed, so KEV flags or EPSS scores may be out of date - check exploit_intel.log.';
                }
                return "{$label}: " . count($s['missing_kb_qids'])
                    . ' knowledge base QID(s) are missing and need looking at - see the sync status panel.';
        }
        return "{$label}: {$s['state']}.";
    }

    private static function when(string $datetime): string
    {
        $ts = strtotime($datetime);
        return $ts === false ? $datetime : date('D j M H:i', $ts);
    }
}
