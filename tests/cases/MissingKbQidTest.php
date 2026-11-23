<?php
declare(strict_types=1);

// QIDs seen in host detections but missing from the local knowledge base are
// queued for scripts/fetch_missing_kb_qids.php and drop off once fetched.

use VulnDash\Lib\Database;
use VulnDash\Lib\MissingKbQidRepository as M;

test('a missing QID is recorded and outstanding', function () {
    $pdo = Database::getConnection();
    M::record($pdo, [999001 => 3]);
    $out = M::outstanding();
    eq(count($out), 1);
    eq((int)$out[0]['qid'], 999001);
    eq((int)$out[0]['hosts'], 3);
    eq(M::needsAttention($out), false, 'fresh and never attempted');
});

test('it drops off once the KB has it', function () {
    $pdo = Database::getConnection();
    M::record($pdo, [999001 => 1, 999002 => 1]);
    $pdo->exec("INSERT INTO knowledge_base (qid, title, severity_level) VALUES (999001, 'now fetched', 3)");
    eq(array_map(fn ($r) => (int)$r['qid'], M::outstanding()), [999002]);
});

test('a failed fetch attempt needs attention', function () {
    $pdo = Database::getConnection();
    M::record($pdo, [999003 => 1]);
    M::markFetchAttempt($pdo, [999003], 'not returned by Qualys');
    eq(M::needsAttention(M::outstanding()), true);
});
