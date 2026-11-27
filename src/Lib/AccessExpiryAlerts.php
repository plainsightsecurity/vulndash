<?php
declare(strict_types=1);

namespace VulnDash\Lib;

/**
 * Daily admin email about access end dates (2026-11-27, see AccessExpiry),
 * sent by scripts/send_expiry_alerts.php:
 *
 *   - "ending":  an organisation or account enters its last
 *                AccessExpiry::WARN_DAYS days - time to chase the renewal.
 *                Also sent straight away if a date is set inside that window.
 *   - "ended":   the date has passed and its members can no longer sign in.
 *
 * Each is sent once per organisation/account per date: move the date on
 * (renewal) and the new one is tracked afresh. Covers active organisations
 * with a date, and active client accounts whose OWN date is the one that
 * applies (earlier than their organisation's, or no organisation date) - an
 * account that just follows its organisation's date is covered by the
 * organisation's line. All of a day's lines go in one email. State in
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

        $items = [];
        foreach ($pdo->query("
            SELECT o.id, o.name, o.expires_on,
                   (SELECT COUNT(*) FROM users u WHERE u.organisation_id = o.id AND u.is_active = 1 AND u.is_admin = 0) AS members
            FROM organisations o
            WHERE o.is_active = 1 AND o.expires_on IS NOT NULL
            ORDER BY o.expires_on, o.name
        ")->fetchAll() as $r) {
            $n = (int)$r['members'];
            $items[] = [
                'key'   => 'org:' . $r['id'] . ':' . $r['expires_on'],
                'date'  => (string)$r['expires_on'],
                'label' => "Organisation {$r['name']} ({$n} active " . ($n === 1 ? 'account' : 'accounts') . ')',
            ];
        }
        foreach ($pdo->query("
            SELECT u.id, u.username, u.expires_on, o.name AS org_name
            FROM users u
            LEFT JOIN organisations o ON o.id = u.organisation_id
            WHERE u.is_admin = 0 AND u.is_active = 1 AND u.expires_on IS NOT NULL
              AND (o.id IS NULL OR o.is_active = 1)
              AND (o.expires_on IS NULL OR u.expires_on < o.expires_on)
            ORDER BY u.expires_on, u.username
        ")->fetchAll() as $r) {
            $items[] = [
                'key'   => 'user:' . $r['id'] . ':' . $r['expires_on'],
                'date'  => (string)$r['expires_on'],
                'label' => "Account {$r['username']}" . ($r['org_name'] !== null ? " ({$r['org_name']})" : ''),
            ];
        }

        $lines = [];
        $next = [];   // state to keep: only items that still exist with the same date
        foreach ($items as $it) {
            $done = $sent[$it['key']] ?? [];
            if (AccessExpiry::isExpired($it['date'], $today)) {
                if (empty($done['ended'])) {
                    $lines[] = "{$it['label']}: access ended after " . AccessExpiry::display($it['date'])
                        . ' - they can no longer sign in. Move the date on to renew, or clear it.';
                    $done['ended'] = $today;
                }
            } elseif (AccessExpiry::isEnding($it['date'], $today) && empty($done['ending'])) {
                $left = AccessExpiry::daysLeft($it['date'], $today);
                $lines[] = "{$it['label']}: access ends after " . AccessExpiry::display($it['date'])
                    . ($left === 1 ? ' - today is the last day.' : " - {$left} days left.");
                $done['ending'] = $today;
            }
            if ($done !== []) {
                $next[$it['key']] = $done;
            }
        }

        $result = ['lines' => $lines, 'sent_to' => []];
        if ($dryRun) {
            return $result;
        }

        if ($lines !== []) {
            $url = rtrim((string)(Config::get('app.base_url') ?? ''), '/') . '/admin/organisations';
            $footer = 'You get this because you are an admin. Each organisation or account is mentioned '
                . AccessExpiry::WARN_DAYS . ' days before its access ends and once more when it ends. '
                . 'Clients see a banner over the same ' . AccessExpiry::WARN_DAYS . ' days.';
            foreach (ApiBudgetAlerts::recipients() as $email => $name) {
                if (Mailer::sendAdminAlertEmail($email, $name, 'access ending', $lines, $url, 'Open Organisations',
                    'These clients\' access is ending or has ended:', $footer)) {
                    $result['sent_to'][] = $email;
                }
            }
            if ($result['sent_to'] === []) {
                return $result;   // nobody got it - leave the state, so tomorrow's run tries again
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
