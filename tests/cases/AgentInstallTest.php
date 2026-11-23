<?php
declare(strict_types=1);

// Agent activation IDs: validation, the exact install commands, setting them
// through Manage Users, and that the Assets page's "Install agent" overlay
// only ever offers an account its own tags' IDs.

use VulnDash\Lib\AgentInstall;
use VulnDash\Lib\Database;

const ID_A = '0888d22d-c088-4e0e-85c3-e4f60f3f3582';
const ID_B = '11111111-2222-3333-4444-555555555555';

test('activation IDs are normalised and anything else refused', function () {
    eq(AgentInstall::normaliseActivationId('  0888D22D-C088-4E0E-85C3-E4F60F3F3582 '), ID_A);
    eq(AgentInstall::normaliseActivationId(''), null);
    eq(AgentInstall::normaliseActivationId('0888d22dc0884e0e85c3e4f60f3f3582'), null, 'no hyphens');
    eq(AgentInstall::normaliseActivationId(ID_A . '; rm -rf /'), null, 'shell injection');
    eq(AgentInstall::normaliseActivationId(ID_A . '"; iex x'), null, 'PowerShell injection');
    eq(AgentInstall::windowsCommand('nope'), null);
    eq(AgentInstall::unixCommand('nope'), null);
});

test('commands match the CE+ onboarding instructions', function () {
    eq(AgentInstall::windowsCommand(ID_A),
        '[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; iex "& { $(irm https://plainsightsecurity.co.uk/agents/installqualysagent.ps1) } -ActivationID ' . ID_A . '"');
    eq(AgentInstall::unixCommand(ID_A),
        'sudo curl -sSL https://plainsightsecurity.co.uk/agents/installqualysagent | sudo bash -s ' . ID_A);
});

test('an admin sets, rejects and clears an activation ID through the real page', function () {
    seed_estate();
    $id = fn () => Database::getConnection()->query('SELECT agent_activation_id FROM tags WHERE id = 1')->fetchColumn();

    $out = render_page('admin/users.php', '', 'admin', 'action=set_activation_id&tag_id=1&agent_activation_id=' . strtoupper(ID_A));
    ok(!str_contains($out, 'PHPERR'), 'no PHP errors: ' . $out);
    eq($id(), ID_A, 'saved in canonical form');

    render_page('admin/users.php', '', 'admin', 'action=set_activation_id&tag_id=1&agent_activation_id=not-a-uuid');
    eq($id(), ID_A, 'invalid value leaves it unchanged');

    $page = render_page('admin/users.php', '', 'admin');
    ok(str_contains($page, 'value="' . ID_A . '"'), 'shown in the Tags table');

    render_page('admin/users.php', '', 'admin', 'action=set_activation_id&tag_id=1&agent_activation_id=');
    eq($id(), null, 'blank clears it');

    $rows = array_values(array_filter(audit_rows(), fn ($r) => $r[0] === 'admin.tag_activation_id'));
    eq(array_map(fn ($r) => [$r[2], $r[3]['activation_id']], $rows), [['ClientA', ID_A], ['ClientA', null]]);
});

test('a client cannot set an activation ID', function () {
    seed_estate();
    $out = render_page('admin/users.php', '', 'client', 'action=set_activation_id&tag_id=1&agent_activation_id=' . ID_A);
    ok(str_contains($out, '403 Forbidden'), 'refused');
    eq(Database::getConnection()->query('SELECT agent_activation_id FROM tags WHERE id = 1')->fetchColumn(), null);
});

test('the Install agent overlay only offers the account its own tags', function () {
    seed_estate();
    $page = render_page('assets.php', '', 'client');
    ok(!str_contains($page, 'id="installAgentOpen"'), 'no button when no tag has an ID');

    Database::getConnection()->exec("UPDATE tags SET agent_activation_id = '" . ID_B . "' WHERE id = 2");
    $page = render_page('assets.php', '', 'client');
    ok(!str_contains($page, 'id="installAgentOpen"'), 'another tenant\'s ID gives this client no button');
    ok(!str_contains($page, ID_B), 'and never leaks');

    Database::getConnection()->exec("UPDATE tags SET agent_activation_id = '" . ID_A . "' WHERE id = 1");
    $page = render_page('assets.php', '', 'client');
    ok(!str_contains($page, 'PHPERR'), 'no PHP errors');
    ok(str_contains($page, 'id="installAgentOpen"'), 'button shown');
    ok(str_contains($page, 'sudo bash -s ' . ID_A), 'unix command with own ID');
    ok(str_contains($page, '-ActivationID ' . ID_A), 'windows command with own ID');
    ok(!str_contains($page, ID_B), 'other tenant still absent');
    ok(!str_contains($page, 'id="installAgentTag"'), 'no tag picker for a single tag');

    $page = render_page('assets.php', '', 'admin');
    ok(str_contains($page, ID_A) && str_contains($page, ID_B), 'admin gets every tag');
    ok(str_contains($page, 'id="installAgentTag"'), 'with a tag picker');

    Database::getConnection()->exec('UPDATE tags SET agent_activation_id = NULL WHERE id = 2');
    $page = render_page('assets.php', 'view_tag=2', 'admin');
    ok(!str_contains($page, 'id="installAgentOpen"'), 'viewing a tag with no ID: no button');
    $page = render_page('assets.php', 'view_tag=1', 'admin');
    ok(str_contains($page, 'id="installAgentOpen"') && !str_contains($page, 'id="installAgentTag"'), 'viewing a tag with an ID: just that tag');
});
