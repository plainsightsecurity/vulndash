<?php
declare(strict_types=1);

// Audit log: what gets recorded, by whom, that a failed audit write never
// breaks the action, the admin page's filters, and that clients can't see it.

use VulnDash\Lib\AuditLog;
use VulnDash\Lib\Auth;
use VulnDash\Lib\Database;

/** Auth needs a live session for session_regenerate_id() - run.php starts one. */
function start_test_session(): void
{
    $_SESSION = [];
}

test('record() uses the session user and stores details', function () {
    seed_estate();
    $_SESSION = ['user_id' => 2, 'username' => 'client'];
    AuditLog::record('scan.requested', ['target_label' => 'host-a', 'details' => ['queued' => 1]]);
    eq(audit_rows(), [['scan.requested', 'client', 'host-a', ['queued' => 1]]]);
});

test('a failed audit write never throws', function () {
    AuditLog::record(str_repeat('x', 300)); // too long for the action column
    eq(audit_rows(), []);
});

test('successful and failed sign-ins', function () {
    seed_estate();
    start_test_session();
    eq(Auth::attemptLogin('client', 'pw-123456789'), Auth::RESULT_SUCCESS);
    eq(Auth::attemptLogin('client', 'wrong-password'), Auth::RESULT_FAILED);
    eq(Auth::attemptLogin('nobody-here', 'whatever'), Auth::RESULT_FAILED);
    $rows = audit_rows();
    eq(array_column($rows, 0), ['auth.login', 'auth.login_failed', 'auth.login_failed']);
    eq([$rows[1][1], $rows[1][3]['reason']], ['client', 'wrong password'], 'attributed to the real account');
    eq([$rows[2][1], $rows[2][2], $rows[2][3]['reason']], [null, 'nobody-here', 'no such account'], 'unknown name kept as target only');
});

test('repeated failures record the lockout', function () {
    seed_estate();
    start_test_session();
    for ($i = 0; $i < 5; $i++) {
        Auth::attemptLogin('client', 'wrong-password');
    }
    $actions = array_column(audit_rows(), 0);
    eq(array_count_values($actions)['auth.login_failed'] ?? 0, 5);
    ok(in_array('auth.account_locked', $actions, true), 'lockout recorded');
});

test('admin user changes are recorded through the real page', function () {
    seed_estate();
    $out = render_page('admin/users.php', '', 'admin', 'action=create_user&username=newbie&email=newbie@test&tag_ids[]=2');
    ok(!str_contains($out, 'PHPERR'), 'no PHP errors: ' . $out);
    $newId = (int)Database::getConnection()->query("SELECT id FROM users WHERE username = 'newbie'")->fetchColumn();
    render_page('admin/users.php', '', 'admin', "action=update_tags&user_id=$newId&tag_ids[]=1&tag_ids[]=2");
    render_page('admin/users.php', '', 'admin', "action=delete_user&user_id=$newId");
    $rows = array_values(array_filter(audit_rows(), fn ($r) => str_starts_with($r[0], 'admin.')));
    eq(array_column($rows, 0), ['admin.user_created', 'admin.user_tags_changed', 'admin.user_deleted']);
    eq(array_column($rows, 1), ['admin', 'admin', 'admin'], 'actor');
    eq(array_column($rows, 2), ['newbie', 'newbie', 'newbie'], 'target name survives deletion');
    eq([$rows[1][3]['before'], $rows[1][3]['after']], [['ClientB'], ['ClientA', 'ClientB']]);
});

test('hiding a finding and exporting a report are recorded', function () {
    seed_estate();
    render_page('vulnerability_detail.php', 'id=1', 'client', 'action=hide_asset&id=1');
    render_page('report_csv.php', '', 'client'); // the hidden finding is left out: 1 of host-a's 2
    $rows = audit_rows();
    eq(array_column($rows, 0), ['finding.hidden', 'report.exported']);
    eq([$rows[0][3]['scope'], $rows[0][3]['asset']], ['this asset', 'host-a']);
    eq([$rows[1][1], $rows[1][3]['format'], $rows[1][3]['rows']], ['client', 'csv', 1]);
});

test('page filters: user, area, action, dates, search', function () {
    $pdo = Database::getConnection();
    $pdo->exec("INSERT INTO audit_log (occurred_at, username, action, target_label, details, ip_address) VALUES
        ('2026-01-10 09:00:00','alice','auth.login',NULL,NULL,'10.1.1.1'),
        ('2026-01-11 09:00:00','bob','admin.user_created','carol','{\"email\":\"carol@x\"}','10.1.1.2'),
        ('2026-01-12 09:00:00','alice','report.exported','PDF - All tags',NULL,'10.1.1.1')");
    eq(AuditLog::count([]), 3);
    eq(AuditLog::count(['user' => 'alice']), 2, 'user');
    eq(AuditLog::count(['area' => 'admin']), 1, 'area');
    eq(AuditLog::count(['action' => 'auth.login']), 1, 'action');
    eq(AuditLog::count(['from' => '2026-01-11', 'to' => '2026-01-11']), 1, 'dates inclusive');
    eq(AuditLog::count(['q' => 'carol']), 1, 'search target/details');
    eq(AuditLog::count(['q' => '10.1.1.1']), 2, 'search IP');
    eq(array_column(AuditLog::search([], 2), 'action'), ['report.exported', 'admin.user_created'], 'newest first');
});

test('old rows are pruned past the retention period', function () {
    $pdo = Database::getConnection();
    $pdo->exec("INSERT INTO audit_log (occurred_at, action) VALUES (NOW() - INTERVAL 400 DAY, 'auth.login'), (NOW() - INTERVAL 10 DAY, 'auth.login')");
    eq(AuditLog::prune(), 1);
    set_config('audit.retention_days', 5);
    eq(AuditLog::prune(), 1);
});

test('the page is admin-only and renders with data', function () {
    seed_estate();
    render_page('report_csv.php', '', 'client');
    $out = render_page('admin/audit_log.php', 'user=client', 'admin');
    ok(str_contains($out, 'Exported a report') && !str_contains($out, 'PHPERR'), 'admin sees it');
    ok(str_contains(render_page('admin/audit_log.php', '', 'client'), '403 Forbidden'), 'client refused');
    $csv = render_page('admin/audit_log.php', 'format=csv', 'admin');
    ok(str_starts_with($csv, "\xEF\xBB\xBF\"Time (UK)\",User,Action"), 'CSV download');
});
