<?php
declare(strict_types=1);

namespace VulnDash\Lib;

/**
 * Emails admins about the Qualys API budget (2026-11-24), checked at the end
 * of every host sync run, including the ones the auto interval skips:
 *
 *   - low:      Qualys last reported alerts.api_budget_low_threshold
 *               (default 5) or fewer calls left on an endpoint and version
 *   - over:     the forecast doesn't fit even at the longest auto interval,
 *               so syncs will start failing for lack of calls
 *   - interval: the auto interval changed (the sync slowed down or sped back
 *               up) - so a slower sync is never a surprise
 *   - scans:    on-demand scan calls in the rolling 24h reached
 *               alerts.ods_busy_calls (default 18 of the 22 budget), so
 *               requests are being paced or will soon wait for the limit
 *               (2026-11-25). Counted locally: Qualys's QPS endpoints don't
 *               report a "calls left" figure.
 *
 * "low" and "over" are sent at most once per 24h per endpoint/version (state
 * in sync_state 'api_budget_alerts'); conditions found in the same run go in
 * one email. Recipients: alerts.admin_emails (a string or list) if set,
 * otherwise every active admin account. Operational detail only - no
 * vulnerability data, the same rule as every other email this app sends.
 */
final class ApiBudgetAlerts
{
    public const DEFAULT_LOW_THRESHOLD = 5;
    public const DEFAULT_ODS_BUSY_CALLS = 18;
    private const REPEAT_SECONDS = 86400;

    private const ENDPOINTS = [
        '/fo/asset/host/vm/detection/' => 'Host Detection',
        '/fo/asset/host/'              => 'Host List',
        '/fo/knowledge_base/vuln/'     => 'KnowledgeBase',
    ];

    /**
     * @param array<string, mixed> $in      ApiBudget::currentInputs()
     * @param array{interval: int, fits: bool, peak: float} $choice ApiBudget::chooseInterval()
     * @param int|null $previousInterval the auto interval before this run decided, if any
     * @return string[] the alert lines sent (empty if nothing new)
     */
    public static function check(array $in, array $choice, ?int $previousInterval, ?int $now = null): array
    {
        $now ??= time();
        $pdo = Database::getConnection();
        $stmt = $pdo->prepare("SELECT state_json FROM sync_state WHERE sync_type = 'api_budget_alerts'");
        $stmt->execute();
        $sent = json_decode((string)$stmt->fetchColumn(), true);
        $sent = is_array($sent) ? $sent : [];

        $lines = [];
        $due = static function (string $key) use (&$sent, $now): bool {
            if (isset($sent[$key]) && $now - (int)$sent[$key] < self::REPEAT_SECONDS) {
                return false;
            }
            $sent[$key] = $now;
            return true;
        };

        if ($previousInterval !== null && $previousInterval !== $choice['interval']) {
            $lines[] = $choice['interval'] > $previousInterval
                ? "The host sync has slowed from every {$previousInterval} to every {$choice['interval']} minutes to stay within the Qualys API limit "
                  . "(forecast at {$previousInterval} minutes: more than " . ApiBudget::usable($in) . " calls a day on the busiest endpoint)."
                : "The host sync is back to every {$choice['interval']} minutes (was {$previousInterval}) - the forecast fits the Qualys API limit again.";
        }

        if (!$choice['fits'] && $due('over')) {
            $lines[] = sprintf(
                'Even at every %d minutes the forecast is about %d calls a day on the busiest endpoint and version, over the %d usable (limit %d, reserve %d). '
                . 'Host syncs will start failing. Options: a larger qualys.host_page_size, fewer reconcile runs, or more API calls from Qualys.',
                $choice['interval'], (int)ceil($choice['peak']), ApiBudget::usable($in), $in['limit'], $in['reserve']
            );
        }

        $threshold = (int)(Config::get('alerts.api_budget_low_threshold') ?? self::DEFAULT_LOW_THRESHOLD);
        foreach (self::ENDPOINTS as $path => $label) {
            foreach (ApiBudget::lastRemaining($path) as $version => $remaining) {
                if ($remaining <= $threshold && $due("low|{$version}|{$path}")) {
                    $lines[] = "/api/{$version}/ {$label}: Qualys reports {$remaining} of {$in['limit']} calls left in the rolling 24 hours.";
                }
            }
        }

        $ods = ScanRequestRepository::sendWindow($now);
        $odsBusy = (int)(Config::get('alerts.ods_busy_calls') ?? self::DEFAULT_ODS_BUSY_CALLS);
        if ($odsBusy > 0 && $ods['calls_24h'] >= $odsBusy && $due('ods_busy')) {
            $lines[] = sprintf(
                'On-demand scans: %d of the %d-a-day budget used in the last 24 hours. New requests are being spread out%s; '
                . 'if this keeps happening, clients will notice scans taking longer to start. Options: a longer qualys.ods_asset_cooldown_minutes, '
                . 'or more API calls from Qualys.',
                $ods['calls_24h'],
                $ods['budget'],
                $ods['next_at'] > $now ? ' (next send from ' . date('H:i', $ods['next_at']) . ')' : ''
            );
        }

        if ($lines === []) {
            return [];
        }

        $pdo->prepare("
            INSERT INTO sync_state (sync_type, state_json) VALUES ('api_budget_alerts', :state)
            ON DUPLICATE KEY UPDATE state_json = VALUES(state_json)
        ")->execute(['state' => json_encode($sent)]);

        $url = rtrim((string)(Config::get('app.base_url') ?? ''), '/') . '/admin/api_usage';
        foreach (self::recipients() as $email => $name) {
            Mailer::sendAdminAlertEmail($email, $name, 'Qualys API budget', $lines, $url);
        }
        return $lines;
    }

    /** @return array<string, string> email => name */
    private static function recipients(): array
    {
        $configured = Config::get('alerts.admin_emails');
        if (is_string($configured) && $configured !== '') {
            $configured = [$configured];
        }
        if (is_array($configured) && $configured !== []) {
            return array_fill_keys(array_map('strval', $configured), '');
        }
        $out = [];
        foreach (Database::getConnection()->query('SELECT email, username FROM users WHERE is_admin = 1 AND is_active = 1')->fetchAll() as $row) {
            $out[(string)$row['email']] = (string)$row['username'];
        }
        return $out;
    }
}
