<?php
declare(strict_types=1);

namespace VulnDash\Lib;

/**
 * Daily admin email about tag access end dates (2026-11-27, see
 * AccessExpiry), sent by scripts/send_expiry_alerts.php:
 *
 *   - "ending": a tag enters its last AccessExpiry::WARN_DAYS days - time to
 *               chase the renewal. Also sent straight away if a date is set
 *               inside that window.
 *   - "ended":  the date has passed and client accounts no longer see it.
 *
 * Each is sent once per tag per date: move the date on (renewal) and the new
 * one is tracked afresh. All of a day's lines go in one email. State in
 * sync_state 'access_expiry_alerts'; if nobody received the email it isn't
 * advanced, so the next run tries again. Recipients as the other admin
 * alerts (alerts.admin_emails, else every active admin).
 */
final class AccessExpiryAlerts
{
    /**
     * @param string|null $today YYYY-MM-DD (tests); default today in Europe/London
     * @return array{lines: string[], sent_to: string[]}
     */
    public static function check(?string $today = null, bool $dryRun = false): array
    {
        $today ??= AccessExpiry::today();
        $pdo = Database::getConnection();
        $stmt = $pdo->prepare("SELECT state_json FROM sync_state WHERE sync_type = 'access_expiry_alerts'");
        $stmt->execute();
        $sent = json_decode((string)$stmt->fetchColumn(), true);
        $sent = is_array($sent) ? $sent : [];

        // Client accounts that have the tag assigned, their own or via an
        // active organisation - the people the date affects.
        $tags = $pdo->query('
            SELECT t.id, t.name, t.expires_on,
                   (SELECT COUNT(DISTINCT e.user_id) FROM ' . UserRepository::EFFECTIVE_TAGS_SQL . ' e
                    JOIN users u ON u.id = e.user_id
                    WHERE e.tag_id = t.id AND u.is_active = 1 AND u.is_admin = 0) AS accounts
            FROM tags t
            WHERE t.expires_on IS NOT NULL
            ORDER BY t.expires_on, t.name
        ')->fetchAll();

        $lines = [];
        $next = [];   // state to keep: only tags that still have the same date
        foreach ($tags as $t) {
            $key = $t['id'] . ':' . $t['expires_on'];
            $done = $sent[$key] ?? [];
            $n = (int)$t['accounts'];
            $label = "{$t['name']} ({$n} client " . ($n === 1 ? 'account' : 'accounts') . ')';
            if (AccessExpiry::isExpired($t['expires_on'], $today)) {
                if (empty($done['ended'])) {
                    $lines[] = "{$label}: access ended after " . AccessExpiry::display($t['expires_on'])
                        . ' - client accounts no longer see its assets. Move the date on to renew, or clear it.';
                    $done['ended'] = $today;
                }
            } elseif (AccessExpiry::isEnding($t['expires_on'], $today) && empty($done['ending'])) {
                $left = AccessExpiry::daysLeft($t['expires_on'], $today);
                $lines[] = "{$label}: access ends after " . AccessExpiry::display($t['expires_on'])
                    . ($left === 0 ? ' - today is the last day.' : ' - in ' . $left . ($left === 1 ? ' day.' : ' days.'));
                $done['ending'] = $today;
            }
            if ($done !== []) {
                $next[$key] = $done;
            }
        }

        $result = ['lines' => $lines, 'sent_to' => []];
        if ($dryRun) {
            return $result;
        }

        if ($lines !== []) {
            $url = rtrim((string)(Config::get('app.base_url') ?? ''), '/') . '/admin/users#tags';
            $footer = 'You get this because you are an admin. Each tag is mentioned '
                . AccessExpiry::WARN_DAYS . ' days before its access ends and once more when it ends. '
                . 'Clients see a notice over the same ' . AccessExpiry::WARN_DAYS . ' days.';
            foreach (ApiBudgetAlerts::recipients() as $email => $name) {
                if (Mailer::sendAdminAlertEmail($email, $name, 'client access ending', $lines, $url, 'Open Manage Users',
                    'Client access to these tags is ending or has ended:', $footer)) {
                    $result['sent_to'][] = $email;
                }
            }
            if ($result['sent_to'] === []) {
                return $result;   // nobody got it - leave the state, so the next run tries again
            }
        }

        if ($next !== $sent) {
            $pdo->prepare("
                INSERT INTO sync_state (sync_type, state_json) VALUES ('access_expiry_alerts', :state) AS new
                ON DUPLICATE KEY UPDATE state_json = new.state_json
            ")->execute(['state' => json_encode($next)]);
        }
        return $result;
    }
}
