<?php
declare(strict_types=1);

namespace VulnDash\Lib;

/**
 * Emails admins when a filesystem the app depends on (see ServerHealth) gets
 * to alerts.disk_warn_percent full (default 85%), and again once it's back
 * under that by ServerHealth::RECOVERY_MARGIN points. Checked every 15
 * minutes by scripts/send_sync_alerts.php, so it needs no cron line of its
 * own. Repeats every alerts.sync_reminder_hours (default 24) while it lasts.
 * If nobody received the email the state isn't advanced, so the next run
 * tries again. State in sync_state 'server_health_alerts'. Same recipients
 * as the other admin alerts. alerts.disk_warn_percent => 0 is treated as the
 * minimum (50); there is no off switch, since a full disk takes everything
 * down with it.
 */
final class ServerHealthAlerts
{
    /**
     * @param array<int, array<string, mixed>>|null $filesystems ServerHealth::filesystems() (tests pass their own)
     * @return array{problems: string[], recoveries: string[], sent_to: string[]}
     */
    public static function check(?int $now = null, bool $dryRun = false, ?array $filesystems = null): array
    {
        $now ??= time();
        $filesystems ??= ServerHealth::filesystems();
        $warn = ServerHealth::warnPercent();
        $reminder = max(0, (int)(Config::get('alerts.sync_reminder_hours') ?? SyncHealthAlerts::DEFAULT_REMINDER_HOURS)) * 3600;

        $pdo = Database::getConnection();
        $stmt = $pdo->prepare("SELECT state_json FROM sync_state WHERE sync_type = 'server_health_alerts'");
        $stmt->execute();
        $saved = json_decode((string)$stmt->fetchColumn(), true);
        $saved = is_array($saved) ? $saved : [];
        $before = $saved;

        $result = ['problems' => [], 'recoveries' => [], 'sent_to' => []];
        $reported = [];
        foreach ($filesystems as $fs) {
            $key = (string)$fs['mount'];
            $prev = $saved[$key] ?? null;
            $desc = self::describe($fs);
            if ($fs['used_pct'] >= $warn) {
                $due = $prev === null || ($reminder > 0 && $now - (int)$prev['last_sent'] >= $reminder);
                if ($due) {
                    $result['problems'][] = ($prev !== null ? 'Still not fixed: ' : '') . $desc
                        . ' When it fills, MySQL, the cron logs and the nightly backups all stop.';
                    $saved[$key] = ['last_sent' => $now];
                    $reported[] = $key;
                }
            } elseif ($prev !== null && $fs['used_pct'] < $warn - ServerHealth::RECOVERY_MARGIN) {
                $result['recoveries'][] = 'Back to normal: ' . $desc;
                unset($saved[$key]);
                $reported[] = $key;
            }
        }

        if ($dryRun) {
            return $result;
        }
        if ($result['problems'] !== [] || $result['recoveries'] !== []) {
            $url = rtrim((string)(Config::get('app.base_url') ?? ''), '/') . '/admin/api_usage#server';
            $lines = array_merge($result['problems'], $result['recoveries']);
            $topic = $result['problems'] !== [] ? 'disk space' : 'disk space back to normal';
            $intro = $result['problems'] !== [] ? null : 'Disk space is back to normal:';
            $footer = "You get this because you are an admin. Sent when a disk reaches {$warn}% full"
                . ($reminder > 0 ? ', every ' . intdiv($reminder, 3600) . ' hours while it stays there,' : '')
                . ' and once it is back under ' . ($warn - ServerHealth::RECOVERY_MARGIN) . '%.';
            foreach (ApiBudgetAlerts::recipients() as $email => $name) {
                if (Mailer::sendAdminAlertEmail($email, $name, $topic, $lines, $url, 'Open API Usage', $intro, $footer)) {
                    $result['sent_to'][] = $email;
                }
            }
            if ($result['sent_to'] === []) {
                foreach ($reported as $key) {   // nobody got it: try again next run
                    if (isset($before[$key])) {
                        $saved[$key] = $before[$key];
                    } else {
                        unset($saved[$key]);
                    }
                }
            }
        }
        if ($saved !== $before) {
            $pdo->prepare("
                INSERT INTO sync_state (sync_type, state_json) VALUES ('server_health_alerts', :state) AS new
                ON DUPLICATE KEY UPDATE state_json = new.state_json
            ")->execute(['state' => json_encode($saved)]);
        }
        return $result;
    }

    /** @param array<string, mixed> $fs */
    public static function describe(array $fs): string
    {
        return sprintf('Disk %s (%s) is %s%% full - %s free of %s.',
            $fs['mount'], implode(', ', $fs['holds']), rtrim(rtrim(number_format((float)$fs['used_pct'], 1), '0'), '.'),
            ServerHealth::bytes((float)$fs['free']), ServerHealth::bytes((float)$fs['total']));
    }
}
