<?php
declare(strict_types=1);

// On-demand scan send pacing (ScanRequestRepository::sendWindow()): bursts
// go every 10 minutes after a quiet spell, steady demand settles to about one
// send every 90 minutes so the 22-a-day budget lasts the day, and the hard 24h limit
// still applies on top.

use VulnDash\Lib\ApiBudgetAlerts;
use VulnDash\Lib\Database;
use VulnDash\Lib\ScanRequestRepository as S;

/** Logs on-demand scan calls at the given times (unix seconds). */
function ods_calls(array $times): void
{
    $stmt = Database::getConnection()->prepare(
        "INSERT INTO qualys_api_call_log (called_at, endpoint, http_status) VALUES (:at, :ep, 200)"
    );
    foreach ($times as $t) {
        $stmt->execute(['at' => date('Y-m-d H:i:s', $t), 'ep' => S::ODS_ENDPOINT]);
    }
}

/**
 * Simulates a steady stream of requests: the worker sends whenever the
 * window allows, checked every 5 minutes from $start for $hours.
 * @return int[] send times
 */
function simulate_sends(int $start, int $hours): array
{
    $sent = [];
    for ($t = $start; $t < $start + $hours * 3600; $t += 300) {
        if (S::sendWindow($t)['next_at'] <= $t) {
            ods_calls([$t]);
            $sent[] = $t;
        }
    }
    return $sent;
}

test('quiet: send straight away', function () {
    $w = S::sendWindow();
    eq([$w['next_at'] <= time(), $w['reason'], $w['burst']], [true, 'now', 6]);
});

test('min gap still batches bursts of clicks', function () {
    $now = time();
    ods_calls([$now - 120]);
    $w = S::sendWindow($now);
    eq([$w['reason'], $w['next_at']], ['gap', $now - 120 + 600]);
});

test('after the burst, sends are paced to about one every 90 minutes', function () {
    $start = time() - 6 * 3600;
    $sent = simulate_sends($start, 6);
    $gaps = array_map(fn ($a, $b) => ($b - $a) / 60, array_slice($sent, 0, -1), array_slice($sent, 1));
    eq(array_slice($gaps, 0, 5), array_fill(0, 5, 10), 'first 6 sends 10 minutes apart');
    ok(min(array_slice($gaps, 6)) >= 85 && max(array_slice($gaps, 6)) <= 95, 'then about every 90 minutes: ' . implode(',', $gaps));
});

test('steady demand all day never runs out', function () {
    $start = time() - 24 * 3600;
    $sent = simulate_sends($start, 24);
    $lastGap = 0;
    foreach (array_slice($sent, 1) as $i => $t) {
        $lastGap = max($lastGap, $t - $sent[$i]);
    }
    ok(count($sent) <= 22, 'within the daily budget: ' . count($sent));
    ok($lastGap <= 95 * 60, 'no wait much over 90 minutes all day, longest ' . round($lastGap / 60) . ' min');
    ok($sent[count($sent) - 1] >= $start + 22 * 3600, 'still sending late in the day');
});

test('without pacing the old behaviour returns (budget gone early)', function () {
    set_config('qualys.ods_burst', 0);
    $start = time() - 24 * 3600;
    $sent = simulate_sends($start, 24);
    eq(count($sent), 22);
    ok($sent[21] < $start + 4 * 3600, 'all 22 used within 4 hours');
    eq(S::sendWindow($sent[21] + 3600)['reason'], 'budget', 'and the rest of the day waits');
});

test('the 24h hard limit still applies', function () {
    set_config('qualys.ods_burst', 0); // pacing off, so only the hard limit is in play
    $now = time();
    ods_calls(array_map(fn ($i) => $now - 20 * 3600 + $i * 700, range(0, 21))); // 22 calls in the window
    $w = S::sendWindow($now);
    eq([$w['calls_24h'], $w['reason'], $w['next_at']], [22, 'budget', $now - 20 * 3600 + 86400]);
});

test('describeNextSend wording', function () {
    $now = strtotime('today 12:00');
    eq(S::describeNextSend(['next_at' => $now + 60, 'reason' => 'gap'], $now), 'within about 5 minutes');
    eq(S::describeNextSend(['next_at' => $now + 3600, 'reason' => 'gap'], $now), 'at about 13:00');
    ok(str_contains(S::describeNextSend(['next_at' => $now + 3600, 'reason' => 'pacing'], $now), 'busy day'), 'pacing explained');
    ok(str_starts_with(S::describeNextSend(['next_at' => $now + 20 * 3600, 'reason' => 'budget'], $now), 'tomorrow at about 08:00'), 'tomorrow');
});

test('admins are emailed once when scans get busy', function () {
    seed_estate();
    $log = tempnam(sys_get_temp_dir(), 'vdmail');
    putenv("VULNDASH_MAIL_LOG=$log");
    try {
        $now = time();
        ods_calls(array_map(fn ($i) => $now - 10 * 3600 + $i * 1800, range(0, 17))); // 18 calls
        $choice = ['interval' => 30, 'fits' => true, 'peak' => 1.0];
        $in = ['limit' => 25, 'reserve' => 0];
        $lines = ApiBudgetAlerts::check($in, $choice, null, $now);
        eq(count($lines), 1);
        ok(str_contains($lines[0], '18 of the 22'), $lines[0]);
        eq(ApiBudgetAlerts::check($in, $choice, null, $now + 600), [], 'not repeated within 24h');
        ok(str_contains((string)file_get_contents($log), 'admin@test'), 'emailed the admin');
    } finally {
        putenv('VULNDASH_MAIL_LOG');
        unlink($log);
    }
});
