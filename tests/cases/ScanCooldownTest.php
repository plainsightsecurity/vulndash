<?php
declare(strict_types=1);

// On-demand scan requests: per-asset cooldown (default 60 min) for
// non-admins, admins exempt, scope enforced.

use VulnDash\Lib\Database;
use VulnDash\Lib\ScanRequestRepository as S;

function sent_scan(int $assetId, int $minsAgo, string $status = 'sent'): void
{
    Database::getConnection()->prepare(
        "INSERT INTO scan_request_queue (asset_id, qualys_host_id, status, requested_by, requested_at, processed_at)
         VALUES (?, ?, ?, 2, NOW() - INTERVAL ? MINUTE, NOW() - INTERVAL ? MINUTE)"
    )->execute([$assetId, 1000 + $assetId, $status, $minsAgo + 5, $minsAgo]);
}

/** cooldown_until is HH:MM; allow the minute boundary to tick over mid-test. */
function cooldown_from_now(int $minutes): array
{
    return [date('H:i', time() + $minutes * 60), date('H:i', time() + $minutes * 60 + 60)];
}

test('fresh asset queues; default cooldown is 60', function () {
    seed_estate();
    eq(S::assetCooldownMinutes(), 60);
    $r = S::enqueue([1], 2, [1], false);
    eq([$r['queued'], $r['cooling_down']], [1, 0]);
});

test('sent 30 minutes ago is refused until the hour is up', function () {
    seed_estate();
    sent_scan(1, 30);
    $r = S::enqueue([1], 2, [1], false);
    eq([$r['queued'], $r['cooling_down']], [0, 1]);
    ok(in_array($r['cooldown_until']['host-a'] ?? '', cooldown_from_now(30), true), 'cooldown_until ~30 min from now');
});

test('sent 61 minutes ago is allowed', function () {
    seed_estate();
    sent_scan(1, 61);
    eq(S::enqueue([1], 2, [1], false)['queued'], 1);
});

test('a failed request does not start a cooldown', function () {
    seed_estate();
    sent_scan(1, 10, 'failed');
    eq(S::enqueue([1], 2, [1], false)['queued'], 1);
});

test('admins are exempt', function () {
    seed_estate();
    sent_scan(1, 5);
    $r = S::enqueue([1], 1, [], true);
    eq([$r['queued'], $r['cooling_down']], [1, 0]);
});

test('out-of-scope assets are refused', function () {
    seed_estate();
    $r = S::enqueue([2, 3], 2, [1], false);
    eq([$r['queued'], $r['not_permitted']], [0, 2]);
});

test('cooldown 0 disables it', function () {
    seed_estate();
    set_config('qualys.ods_asset_cooldown_minutes', 0);
    sent_scan(1, 5);
    eq(S::enqueue([1], 2, [1], false)['queued'], 1);
});
