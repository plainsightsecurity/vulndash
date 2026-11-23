<?php
declare(strict_types=1);

// Top fixes: QIDs ranked by the dashboard gauge's own risk points, scoped
// like everything else, adding up to the gauge's total.

use VulnDash\Lib\Database;
use VulnDash\Lib\VulnerabilityRepository as V;

test('ranked by risk points, KEV critical first', function () {
    seed_estate();
    $fixes = V::getTopFixes([], true);
    eq(array_column($fixes, 'qid'), [5001, 5002, 5003, 5004]);
    // Defaults: Critical 40 x KEV 5 = 200; High 10 x EPSS>=10% 1.5 = 15; Medium 3; Low 1.
    eq(array_column($fixes, 'risk_points'), [200.0, 15.0, 3.0, 1.0]);
    eq($fixes[0]['is_kev'], true);
});

test('points add up to the dashboard gauge', function () {
    seed_estate();
    $sum = array_sum(array_column(V::getTopFixes([], true), 'risk_points'));
    eq($sum, (float)V::getRiskScore([], true)['risk_points']);
    $sum = array_sum(array_column(V::getTopFixes([1], false, null, 2), 'risk_points'));
    eq($sum, (float)V::getRiskScore([1], false, null, false, 2)['risk_points'], 'client scope');
});

test('one QID on many assets outranks a single worse finding', function () {
    seed_estate();
    $pdo = Database::getConnection();
    // 5003 (Medium, 3 pts each) on 80 more assets in ClientA = 243 pts > 5001's 200.
    for ($i = 100; $i < 180; $i++) {
        $pdo->exec("INSERT INTO assets (id, qualys_host_id, hostname) VALUES ($i, " . (5000 + $i) . ", 'bulk-$i')");
        $pdo->exec("INSERT INTO asset_tags (asset_id, tag_id) VALUES ($i, 1)");
        $pdo->exec("INSERT INTO host_detections (asset_id, qid, status, first_found, last_found, times_found, effective_cvss_score, effective_cvss_source, is_ce_plus_fail)
                    VALUES ($i, 5003, 'Active', NOW(), NOW(), 1, 5.3, 'CVSS3', 0)");
    }
    $top = V::getTopFixes([1], false, null, 2)[0];
    eq([$top['qid'], $top['assets']], [5003, 81]);
});

test('client sees only their own QIDs', function () {
    seed_estate();
    eq(array_column(V::getTopFixes([1], false, null, 2), 'qid'), [5001, 5003]);
    eq(V::getTopFixes([], false, null, 2), [], 'no tags');
});

test('fixed findings drop out', function () {
    seed_estate();
    Database::getConnection()->exec("UPDATE host_detections SET status = 'Fixed' WHERE qid = 5001");
    eq(array_column(V::getTopFixes([], true), 'qid'), [5002, 5003, 5004]);
});

test('score after fixing uses the gauge curve', function () {
    seed_estate();
    $risk = V::getRiskScore([], true);
    eq(V::riskScoreFor((float)$risk['risk_points'], $risk['assets']), $risk['score']);
    eq(V::riskScoreFor(0.0, 3), 0);
});
