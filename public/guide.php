<?php
declare(strict_types=1);

require_once __DIR__ . '/../src/bootstrap.php';

use VulnDash\Lib\AgentInstall;
use VulnDash\Lib\Auth;
use VulnDash\Lib\CePlusDeadline;
use VulnDash\Lib\Helpers;
use VulnDash\Lib\ScanRequestRepository;
use VulnDash\Lib\StaleAgent;
use VulnDash\Lib\UserRepository;

// User guide. Every figure, host, tag and finding shown here is made-up
// example data, rendered with the app's own classes so it looks like the real
// pages - nothing is read from the vulnerability tables, so the guide can't
// leak another tenant's data whoever views it.
//
// Sections are gated by the same checks the real pages use, so a client only
// reads about controls it will actually see: admin tools need isAdmin(), agent
// uninstall needs canUninstall(), and "Install agent" needs one of the
// account's own tags to carry an activation ID (assets.php's condition).
Auth::check();

$isAdmin      = Auth::isAdmin();
$canUninstall = Auth::canUninstall();

$availableTags = $isAdmin ? UserRepository::listTags() : UserRepository::getTagsByIds(Auth::tagIds());
$canInstall    = AgentInstall::installableTags($availableTags) !== [];

$patchDays    = CePlusDeadline::PATCH_WINDOW_DAYS;
$staleDays    = StaleAgent::staleAfterDays();
$cooldownMins = ScanRequestRepository::assetCooldownMinutes();

// [anchor => [title, shown?, admin-only?]] - drives both the contents list and
// which sections render below, so the two can't disagree.
$sections = [
    'getting-started' => ['Signing in', true, false],
    'tags'            => ['Choosing what you see', true, false],
    'dashboard'       => ['Dashboard', true, false],
    'vulnerabilities' => ['Vulnerabilities', true, false],
    'detail'          => ['A single finding', true, false],
    'hiding'          => ['Hiding findings', true, false],
    'assets'          => ['Assets and scans', true, false],
    'ce-readiness'    => ['CE+ Readiness', true, false],
    'trends'          => ['Trends', true, false],
    'top-fixes'       => ['Top fixes', true, false],
    'search'          => ['Search', true, false],
    'reports'         => ['Reports', true, false],
    'account'         => ['Your account', true, false],
    'glossary'        => ['Glossary', true, false],
    'org-admin'       => ['My organisation', !$isAdmin && !empty($_SESSION['is_org_admin']), false],
    'admin-users'     => ['Manage Users', $isAdmin, true],
    'admin-orgs'      => ['Organisations', $isAdmin, true],
    'admin-audit'     => ['Audit Log', $isAdmin, true],
    'admin-api'       => ['API Usage', $isAdmin, true],
];
$show = array_map(static fn (array $s): bool => $s[1], $sections);

$pageTitle = 'User guide';
require __DIR__ . '/../src/views/header.php';
?>

<div class="page-heading">
    <h1>User guide</h1>
    <p class="page-subtitle">How to use the dashboard<?= $isAdmin ? ', including the admin tools' : '' ?>. The examples use made-up data, so they won't match your own figures.</p>
</div>

<div class="guide-layout">

<nav class="guide-toc" aria-label="Guide contents">
    <span class="guide-toc-heading">Contents</span>
    <ol>
        <?php foreach ($sections as $anchor => [$title, $visible, $adminOnly]): if (!$visible) continue; ?>
        <li><a href="#<?= $anchor ?>"><?= Helpers::e($title) ?></a><?= $adminOnly ? ' <span class="badge badge-accent guide-admin-badge">Admin</span>' : '' ?></li>
        <?php endforeach; ?>
    </ol>
</nav>

<div class="guide-content">

<!-- ================================================================== -->
<section class="guide-section" id="getting-started">
    <h2>Signing in</h2>
    <p>Sign in at <span class="mono">dashboard.plainsightsecurity.co.uk</span> with your username or email address and your password.</p>
    <ul>
        <li>If two-factor authentication is on for your account, you'll then be asked for the 6-digit code from your authenticator app. Tick <strong>Trust this device for 30 days</strong> to skip the code on that browser for 30 days.</li>
        <li>Forgotten your password? Use <strong>Forgot your password?</strong> on the sign-in page and a reset link is emailed to you.</li>
        <li>After 5 failed attempts in a row, sign-in is paused for 15 minutes.</li>
    </ul>
    <p>The menu along the top takes you to each page. Your name at the top right opens the account menu (Preferences, Password, Security, this guide and Log out)<?= $isAdmin ? ', plus the admin tools' : '' ?>. The sun/moon button switches between dark and light themes.</p>
</section>

<!-- ================================================================== -->
<section class="guide-section" id="tags">
    <h2>Choosing what you see</h2>
    <?php if ($isAdmin): ?>
    <p>As an admin you see every monitored asset. Each asset belongs to one or more <strong>tags</strong> (usually one per client), and the <strong>Tags</strong> drop-down at the top of each page narrows every figure to one tag.</p>
    <?php else: ?>
    <p>You only ever see the assets in the <strong>tags</strong> assigned to your account. If you have more than one tag, the <strong>Tags</strong> drop-down at the top of each page narrows every figure to just one of them.</p>
    <?php endif; ?>
    <div class="guide-example" inert>
        <span class="guide-example-label">Example</span>
        <div class="filter-bar">
            <label class="field field-inline">
                <span>Tags</span>
                <select><option>Northwind Ltd</option></select>
            </label>
        </div>
    </div>
    <p>The tag you pick follows you between pages for the rest of your session. To open on a particular tag every time you sign in, set a default tag in <a href="#account">Preferences</a>.</p>
</section>

<!-- ================================================================== -->
<section class="guide-section" id="dashboard">
    <h2>Dashboard</h2>
    <p>The dashboard is a summary of current open exposure. It starts with a one-line summary, then the <strong>risk score</strong>.</p>

    <div class="guide-example" inert>
        <span class="guide-example-label">Example</span>
        <p class="dashboard-posture"><strong>1,284</strong> open findings across <strong>48</strong> assets — <strong>37</strong> critical, <strong>212</strong> high, <strong>61</strong> failing Cyber Essentials Plus.</p>
        <?php
        // The real gauge partial, fed a fixed example score.
        $risk = ['score' => 62, 'band' => 'High', 'band_class' => 'sev-high', 'risk_points' => 0.0, 'findings' => 1284, 'kev_findings' => 9, 'assets' => 48, 'density' => 0.0];
        require __DIR__ . '/../src/views/risk_gauge.php';
        ?>
    </div>
    <p>The risk score runs from 0 to 100 (higher is worse): <span class="badge sev-low">Low</span> under 25, <span class="badge sev-medium">Medium</span> 25–49, <span class="badge sev-high">High</span> 50–74 and <span class="badge sev-critical">Critical</span> 75 and over. It weighs each open finding by severity, and more heavily if it's known to be exploited. <a href="#top-fixes">Top fixes</a> shows what would bring it down fastest.</p>

    <p>Below it, the summary cards. Click any card to open the matching list.</p>
    <div class="guide-example" inert>
        <span class="guide-example-label">Example</span>
        <div class="stat-grid">
            <div class="stat-card stat-card-primary"><span class="stat-number">48</span><span class="stat-label">Assets</span></div>
            <div class="stat-card sev-critical"><span class="stat-number">37</span><span class="stat-label">Critical</span></div>
            <div class="stat-card sev-high"><span class="stat-number">212</span><span class="stat-label">High</span></div>
            <div class="stat-card sev-medium"><span class="stat-number">803</span><span class="stat-label">Medium</span></div>
            <div class="stat-card sev-low"><span class="stat-number">232</span><span class="stat-label">Low</span></div>
            <div class="stat-card stat-card-kev"><span class="stat-number">9</span><span class="stat-label">Known exploited</span></div>
            <div class="stat-card sev-critical"><span class="stat-number">4</span><span class="stat-label">CE+ overdue</span></div>
            <div class="stat-card sev-medium"><span class="stat-number">2</span><span class="stat-label">Not reporting</span></div>
        </div>
    </div>
    <ul>
        <li><strong>Known exploited</strong> - findings on the CISA list of vulnerabilities attackers are actively using. Patch these first.</li>
        <li><strong>CE+ overdue</strong> - Cyber Essentials Plus failures not patched within <?= $patchDays ?> days of the vendor releasing the fix. These would fail an assessment today.</li>
        <li><strong>Not reporting</strong> - assets whose agent hasn't reported in over <?= $staleDays ?> days, so their figures may be out of date.</li>
    </ul>
    <p>Then come the charts: findings by severity, the total open over the last 30 days (hover for each day's figure), and findings by category and by operating system. Click a bar or a section to open those findings. The full-screen button on each chart enlarges it. The <strong>Top 10 most detected vulnerabilities</strong> table lists the issues found on the most assets, and the banner at the bottom shows how many findings currently fail Cyber Essentials Plus, with a button to list them.</p>

    <?php if ($isAdmin): ?>
    <div class="guide-admin-note">
        <span class="badge badge-accent">Admin</span>
        Admins also see sync status cards above the tag selector, one per Qualys sync job: last success, whether it's running, overdue or failed (with the error), and any QIDs agents have reported that aren't yet in the local knowledge base, with the command to fetch them.
    </div>
    <?php endif; ?>
</section>

<!-- ================================================================== -->
<section class="guide-section" id="vulnerabilities">
    <h2>Vulnerabilities</h2>
    <p>Every open finding, one row per vulnerability on each asset (fixed findings drop off automatically). Click a column heading to sort, or a title to open the finding.</p>
    <div class="guide-example" inert>
        <span class="guide-example-label">Example</span>
        <div class="filter-bar">
            <label class="field field-inline"><span>Severity</span><select><option>Critical</option></select></label>
            <label class="checkbox-field"><input type="checkbox" checked><span>CE+ failures only <span class="checkbox-hint">(CVSS &ge; 7.0, excl. zero-days)</span></span></label>
            <label class="checkbox-field"><input type="checkbox"><span>CE+ overdue only</span></label>
            <label class="checkbox-field"><input type="checkbox"><span>Known exploited only <span class="checkbox-hint">(CISA KEV)</span></span></label>
            <label class="field field-inline"><span>EPSS</span><select><option>Any</option></select></label>
            <label class="field field-inline"><span>Search</span><input type="text" value="chrome"></label>
        </div>
        <div class="table-wrap">
        <table class="vuln-table">
            <thead><tr><th>Asset</th><th>QID</th><th>Title</th><th>Severity</th><th>CVSS</th><th>EPSS</th><th>CE+ due</th><th>Status</th><th>Last found</th></tr></thead>
            <tbody>
                <tr class="sev-critical-row"><td>NW-LT-014</td><td class="mono">379901</td><td>Google Chrome Prior to 131.0.6778.85 Multiple Vulnerabilities <span class="badge badge-kev">KEV</span></td><td><span class="badge sev-critical">Critical</span></td><td class="mono">9.8</td><td class="mono">94.1%</td><td class="mono"><span class="badge badge-ce-fail">Overdue 3d</span></td><td>Active</td><td class="mono">2026-11-22 06:14</td></tr>
                <tr class="sev-critical-row"><td>NW-SRV-DC01</td><td class="mono">379901</td><td>Google Chrome Prior to 131.0.6778.85 Multiple Vulnerabilities <span class="badge badge-kev">KEV</span></td><td><span class="badge sev-critical">Critical</span></td><td class="mono">9.8</td><td class="mono">94.1%</td><td class="mono">5d left</td><td>New</td><td class="mono">2026-11-22 05:51</td></tr>
                <tr class="sev-high-row"><td>NW-MBP-007</td><td class="mono">378812</td><td>Google Chrome Extension Framework Flaw <span class="badge badge-potential">Potential</span></td><td><span class="badge sev-high">High</span></td><td class="mono">7.5</td><td class="mono">0.4%</td><td class="mono">—</td><td>Active</td><td class="mono">2026-11-21 19:02</td></tr>
            </tbody>
        </table>
        </div>
    </div>
    <ul>
        <li><strong>Severity</strong> and the tick boxes narrow the list. <em>CE+ failures</em> and <em>CE+ overdue</em> only apply to Critical and High, so they disappear if you choose Medium or Low.</li>
        <li><strong>EPSS</strong> keeps only findings with at least that chance of being exploited in the next 30 days.</li>
        <li><strong>Search</strong> matches titles, hostnames and QIDs as you type.</li>
        <li><strong>CE+ due</strong> counts down the <?= $patchDays ?>-day patch window from when the vendor released the fix, and turns red once overdue.</li>
        <li>Filters set by clicking through from another page (a QID, CVE, category, OS or age band) show as chips above the table. Click the &times; on a chip to remove it.</li>
    </ul>
    <p>Clicking a hostname on the <a href="#assets">Assets</a> page opens this list for just that asset.</p>
</section>

<!-- ================================================================== -->
<section class="guide-section" id="detail">
    <h2>A single finding</h2>
    <p>Opening a finding shows everything known about it: badges across the top, then the host, the detection history and the scoring.</p>
    <div class="guide-example" inert>
        <span class="guide-example-label">Example</span>
        <p class="guide-badge-row">
            <span class="badge sev-critical">Critical</span>
            <span class="badge badge-ce-fail">CE+ Fail</span>
            <span class="badge badge-ce-fail">Patch overdue · 3 days</span>
            <span class="badge badge-neutral mono">CVSS 9.8</span>
            <span class="badge badge-kev">KEV</span>
            <span class="badge badge-neutral mono">EPSS 94.1%</span>
            <span class="badge badge-neutral">Patchable</span>
        </p>
        <div class="detail-grid">
            <div class="panel">
                <h2>Host</h2>
                <dl class="kv-list">
                    <dt>Hostname</dt><dd>NW-LT-014</dd>
                    <dt>IP address</dt><dd class="mono">10.20.4.114</dd>
                    <dt>Operating system</dt><dd>Windows 11 Pro 23H2</dd>
                    <dt>Last agent report</dt><dd class="mono">2026-11-22 06:14</dd>
                </dl>
            </div>
            <div class="panel">
                <h2>Detection</h2>
                <dl class="kv-list">
                    <dt>Status</dt><dd>Active</dd>
                    <dt>First found</dt><dd class="mono">2026-11-04 08:30</dd>
                    <dt>Last found</dt><dd class="mono">2026-11-22 06:14</dd>
                    <dt>Times found</dt><dd class="mono">19</dd>
                </dl>
            </div>
            <div class="panel">
                <h2>Scoring</h2>
                <dl class="kv-list">
                    <dt>CVSS v3 base</dt><dd class="mono">9.8</dd>
                    <dt>CISA KEV</dt><dd>Listed</dd>
                    <dt>CE+ patch due</dt><dd class="mono">2026-11-19 <span class="muted">(Overdue 3d)</span></dd>
                    <dt>Patch released</dt><dd class="mono">2026-11-05</dd>
                </dl>
            </div>
        </div>
    </div>
    <p>Below that are the CVEs it covers (each links to its CVE record), Qualys's <strong>Diagnosis</strong> and <strong>Consequence</strong>, and the <strong>Solution</strong>. A <span class="badge badge-accent">Custom</span> badge on the solution means your security team has written their own remediation steps for this vulnerability, shown in place of Qualys's text.</p>
    <p>Other badges you may see: <span class="badge badge-potential">Potential</span> (Qualys couldn't fully confirm it), <span class="badge badge-neutral">Zero-day · No fix yet</span> (no vendor patch exists, so it doesn't count as a CE+ failure) and <span class="badge sev-medium">Not reporting · 12 days</span> (the asset's agent has gone quiet, so this may be out of date).</p>

    <?php if ($isAdmin): ?>
    <div class="guide-admin-note">
        <span class="badge badge-accent">Admin</span>
        Admins get a <strong>Custom remediation</strong> panel at the bottom of each finding. Text saved there replaces the Qualys solution for every detection of that QID, for every account. It opens pre-filled with the current text (and the Qualys original is available for reference), so you can edit rather than retype. Links in the Qualys text are kept.
    </div>
    <?php endif; ?>
</section>

<!-- ================================================================== -->
<section class="guide-section" id="hiding">
    <h2>Hiding findings</h2>
    <p>If a finding is accepted or not relevant to you, you can hide it from your counts and lists. Open the finding and use <strong>Hide finding</strong>:</p>
    <ul>
        <li><strong>Hide on this asset only</strong> - just this one occurrence.</li>
        <li><strong>Hide on every asset tagged …</strong> (when a tag is selected) or <strong>Hide across all my assets</strong> - this vulnerability wherever it appears.</li>
    </ul>
    <div class="guide-example" inert>
        <span class="guide-example-label">Example</span>
        <span class="hidden-chip"><span><strong>3</strong> hidden</span></span>
        <span class="badge badge-hidden">Hidden · This asset</span>
    </div>
    <p>Hiding is personal: it only changes your own view, never anyone else's. Click the <strong>N hidden</strong> chip on the dashboard or vulnerability list to bring hidden findings back into view (they're marked <span class="badge badge-hidden">Hidden</span>), and again to tuck them away. To undo a hide, open the finding and choose <strong>Unhide finding</strong>.</p>
    <p><strong>Hiding doesn't fix anything.</strong> A hidden finding is still on the machine and still counts on the <a href="#ce-readiness">CE+ Readiness</a> page and in a real assessment.</p>
</section>

<!-- ================================================================== -->
<section class="guide-section" id="assets">
    <h2>Assets and scans</h2>
    <p>Every machine with a Qualys agent, with its open findings by severity. Search by hostname, IP address or operating system, or tick <strong>Not reporting only</strong> to find agents that haven't reported in <?= $staleDays ?>+ days. Click a hostname to see its findings.</p>
    <div class="guide-example" inert>
        <span class="guide-example-label">Example</span>
        <div class="bulk-actions">
            <button type="button" class="btn btn-sm btn-secondary">Scan selected now</button>
            <?php if ($canUninstall): ?><button type="button" class="btn btn-sm btn-danger">Uninstall agent on selected</button><?php endif; ?>
        </div>
        <div class="table-wrap">
        <table class="vuln-table">
            <thead><tr><th class="checkbox-col"><input type="checkbox"></th><th>Hostname</th><th>IP address</th><th>OS</th><th>Last scan</th><th>Critical</th><th>High</th><th>CE+ fails</th><th>Open vulns</th></tr></thead>
            <tbody>
                <tr><td class="checkbox-col"><input type="checkbox" checked></td><td>NW-LT-014</td><td class="mono">10.20.4.114</td><td>Windows 11 Pro 23H2</td><td class="last-scan-cell"><span class="mono">2026-11-22 06:14</span> <span class="badge badge-scan badge-accent">Scan queued</span></td><td class="mono">6</td><td class="mono">14</td><td class="mono">9</td><td class="mono">58</td></tr>
                <tr><td class="checkbox-col"><input type="checkbox"></td><td>NW-SRV-DC01</td><td class="mono">10.20.1.10</td><td>Windows Server 2022</td><td class="last-scan-cell"><span class="mono">2026-11-22 05:51</span></td><td class="mono">3</td><td class="mono">11</td><td class="mono">7</td><td class="mono">41</td></tr>
                <tr><td class="checkbox-col"><input type="checkbox"></td><td>nw-web-01</td><td class="mono">10.20.8.21</td><td>Ubuntu 22.04</td><td class="last-scan-cell"><span class="badge sev-medium badge-stale">12 days ago</span></td><td class="mono">0</td><td class="mono">2</td><td class="mono">2</td><td class="mono">17</td></tr>
            </tbody>
        </table>
        </div>
    </div>

    <h3>Scanning on demand</h3>
    <p>Agents scan on their own schedule. To get fresh results sooner (after patching, say), tick the assets and press <strong>Scan selected now</strong>. Requests go to Qualys together, normally within about 10 minutes. On a very busy day they're spread out so there's allowance left for later, and the chip shows when they'll go (for example <span class="badge badge-accent">Scan queued · 14:20</span>). The <span class="badge badge-accent">Scan queued</span> chip changes to <span class="badge badge-accent">Scan requested</span> once sent, and new results appear after the agent has scanned and Qualys has processed them.<?php if ($cooldownMins > 0): ?> Each asset can be scanned on request once every <?= $cooldownMins ?> minutes.<?php endif; ?></p>

    <?php if ($canInstall): ?>
    <h3>Installing the agent on a new machine</h3>
    <p>Select your tag from the <strong>Tags</strong> drop-down and an <strong>Install agent</strong> button appears at the top of the Assets page. It gives a one-line install command for Windows and for macOS/Linux, with your organisation's activation ID already built in; press <strong>Copy</strong> and paste it into:</p>
    <ul>
        <li><strong>Windows</strong> - PowerShell opened with <em>Run as administrator</em>. You don't need to be signed in to Windows as an administrator; enter an administrator's username and password when Windows asks.</li>
        <li><strong>macOS / Linux</strong> - Terminal, from an account with administrator (sudo) rights. It asks for that account's password, and nothing shows as you type it.</li>
    </ul>
    <p>The new machine appears under Assets once its agent first reports to Qualys and the next dashboard sync runs.</p>
    <?php endif; ?>

    <?php if ($canUninstall): ?>
    <h3>Uninstalling the agent</h3>
    <p>Your account can also remove agents from machines that have been retired. Tick them and press <strong>Uninstall agent on selected</strong>, then confirm. They leave the dashboard straight away and the agent is uninstalled on the next processing run. Use this with care: it can't be undone from the dashboard, and a machine still in use will stop being monitored.</p>
    <?php endif; ?>
</section>

<!-- ================================================================== -->
<section class="guide-section" id="ce-readiness">
    <h2>CE+ Readiness</h2>
    <p>Whether each host would pass a Cyber Essentials Plus assessment on what Qualys reports today.</p>
    <div class="guide-example" inert>
        <span class="guide-example-label">Example</span>
        <div class="stat-grid readiness-grid">
            <div class="stat-card stat-card-primary"><span class="stat-number">71%</span><span class="stat-label">Would pass today</span><span class="movement-card-hint">34 of 48 hosts</span></div>
            <div class="stat-card readiness-fail"><span class="stat-number">5</span><span class="stat-label">Failing</span><span class="movement-card-hint">End-of-life, or patch overdue</span></div>
            <div class="stat-card readiness-risk"><span class="stat-number">9</span><span class="stat-label">At risk</span><span class="movement-card-hint">Pass today, patch due soon</span></div>
            <div class="stat-card readiness-pass"><span class="stat-number">34</span><span class="stat-label">Passing</span><span class="movement-card-hint">Nothing to patch</span></div>
        </div>
    </div>
    <ul>
        <li><strong>Failing</strong> - the host has end-of-life software (always a fail, whatever its score), or a CE+ finding whose patch was released more than <?= $patchDays ?> days ago.</li>
        <li><strong>At risk</strong> - passes today, but has CE+ findings still inside the <?= $patchDays ?>-day window. Patch them before they fall due.</li>
        <li><strong>Passing</strong> - nothing to patch.</li>
    </ul>
    <p>A <strong>CE+ finding</strong> is one with a CVSS score of 7.0 or above (the CVSS v3 score if there is one, otherwise v2, otherwise estimated from the Qualys severity). Zero-days with no vendor fix yet don't count; they're shown in the <em>No fix</em> column for information only. Hidden findings still count here.</p>
    <p>The <strong>By tag</strong> table shows each tag's assessment date, if one has been set, and how many hosts are projected to fail on that date if nothing more is patched. The host list has tabs (Needs attention, Failing, At risk, Passing, All hosts), and <strong>Next deadlines</strong> lists the CE+ findings due soonest. Hosts that have stopped reporting keep their last known status, marked with how long ago they last reported, e.g. <span class="badge sev-medium">12 days ago</span>.</p>
    <?php if ($isAdmin): ?>
    <div class="guide-admin-note">
        <span class="badge badge-accent">Admin</span>
        Admins set each tag's assessment date in the <strong>By tag</strong> table: pick the date and press <strong>Save</strong>; clear it and save to remove it. Every account with access to that tag sees the date.
    </div>
    <?php else: ?>
    <p>Assessment dates are set by Plainsight Security. Ask us if yours is missing or has changed.</p>
    <?php endif; ?>
</section>

<!-- ================================================================== -->
<section class="guide-section" id="trends">
    <h2>Trends</h2>
    <p>What's changed recently, over the last 7, 30 or 90 days (choose with <strong>Window</strong>).</p>
    <div class="guide-example" inert>
        <span class="guide-example-label">Example</span>
        <div class="stat-grid">
            <div class="stat-card movement-new"><span class="stat-number">143</span><span class="stat-label">New findings</span></div>
            <div class="stat-card movement-resolved"><span class="stat-number">208</span><span class="stat-label">Resolved</span></div>
            <div class="stat-card movement-reopened"><span class="stat-number">6</span><span class="stat-label">Re-opened</span></div>
        </div>
    </div>
    <ul>
        <li><strong>Movement</strong> - findings that appeared, were fixed, or came back after being fixed.</li>
        <li><strong>Remediation aging</strong> - open findings by severity and how long they've been open (0–7, 8–30, 31–90 and over 90 days). Click any number to list those findings.</li>
        <li><strong>Recently resolved</strong> - what's been fixed in the window.</li>
    </ul>
</section>

<!-- ================================================================== -->
<section class="guide-section" id="top-fixes">
    <h2>Top fixes</h2>
    <p>The vulnerabilities that would take the most off your risk score if patched everywhere they appear, ranked by severity, active exploitation and how many assets have them. Choose to show the top 25, 50 or 100.</p>
    <div class="guide-example" inert>
        <span class="guide-example-label">Example</span>
        <p class="report-summary-line report-summary-count">Fixing the top 10 would remove 58% of the risk behind your score, taking it from 62 to 31.</p>
        <div class="table-wrap">
        <table class="vuln-table">
            <thead><tr><th class="col-num">#</th><th>QID</th><th>Title</th><th>Severity</th><th class="col-num">CVSS</th><th class="col-num">Assets</th><th>Share of risk</th><th class="col-num">Cumulative</th></tr></thead>
            <tbody>
                <tr><td class="col-num mono">1</td><td class="mono">379901</td><td>Google Chrome Prior to 131.0.6778.85 Multiple Vulnerabilities <span class="badge badge-kev">KEV</span></td><td><span class="badge sev-critical">Critical</span></td><td class="col-num mono">9.8</td><td class="col-num mono">31</td><td>18%</td><td class="col-num mono">18%</td></tr>
                <tr><td class="col-num mono">2</td><td class="mono">92170</td><td>Microsoft Windows Security Update - November 2026</td><td><span class="badge sev-critical">Critical</span></td><td class="col-num mono">8.8</td><td class="col-num mono">27</td><td>11%</td><td class="col-num mono">29%</td></tr>
            </tbody>
        </table>
        </div>
    </div>
    <p><strong>Cumulative</strong> is the running total: fixing that row and every row above it. It's the quickest way to decide what to patch first.</p>
</section>

<!-- ================================================================== -->
<section class="guide-section" id="search">
    <h2>Search</h2>
    <p>The magnifying glass in the menu checks whether you're affected by a particular CVE, or finds a QID, host or vulnerability by name. Searching for a CVE gives a straight answer:</p>
    <div class="guide-example" inert>
        <span class="guide-example-label">Example</span>
        <div class="search-verdict search-verdict-affected"><strong>Affected.</strong> 3 hosts have CVE-2026-10001.</div>
        <div class="search-verdict search-verdict-clear"><strong>Not affected.</strong> Qualys checks for CVE-2026-10002, and none of your hosts currently has it.</div>
        <div class="search-verdict search-verdict-unknown"><strong>Can't tell.</strong> Qualys has no detection for CVE-2026-10003 yet, so the agents can't check for it.</div>
    </div>
    <p>"Not affected" covers machines with a Qualys agent only. "Can't tell" doesn't mean you're safe: check the vendor's advisory, or search again in a day or two. Any other search lists matching open vulnerabilities and hosts.</p>
</section>

<!-- ================================================================== -->
<section class="guide-section" id="reports">
    <h2>Reports</h2>
    <p>Export findings for sharing or for your own records. Choose the tag, severity, CE+ failures only, known exploited only and EPSS threshold; the page shows the scope and how many findings will be included, then:</p>
    <ul>
        <li><strong>PDF</strong> - a summary plus a findings table, ordered by severity and capped at the 2,000 most severe findings.</li>
        <li><strong>CSV</strong> - every matching finding, one per row, with no cap, for Excel or another tool.</li>
    </ul>
    <p>Reports leave out findings you've hidden.</p>
</section>

<!-- ================================================================== -->
<section class="guide-section" id="account">
    <h2>Your account</h2>
    <p>From the account menu under your name:</p>
    <h3>Preferences</h3>
    <ul>
        <li><strong>Default tag</strong> - the tag the dashboard opens on each time you sign in.</li>
        <li><strong>Email notifications</strong> - Off, Daily or Weekly emails when there's new activity. Off unless you turn it on.</li>
        <li><strong>Exploited-vulnerability alerts</strong> - an email straight away when a vulnerability on the CISA known-exploited list newly appears on <?= $isAdmin ? 'any monitored system' : 'one of your systems' ?>. On by default.</li>
    </ul>
    <p>For your security, these emails never include vulnerability details (no asset names, findings or counts), just a prompt to sign in.</p>
    <h3>Password</h3>
    <p>Enter your current password and a new one of at least 12 characters.</p>
    <h3>Security (two-factor authentication)</h3>
    <p>Choose <strong>Enable two-factor authentication</strong>, scan the QR code with an authenticator app (Microsoft Authenticator, Google Authenticator, 1Password and so on) or type in the key shown, then enter a code to confirm. The same page lists your <strong>trusted devices</strong>; revoke any you don't recognise, or all of them at once.</p>
</section>

<!-- ================================================================== -->
<section class="guide-section" id="glossary">
    <h2>Glossary</h2>
    <dl class="guide-glossary">
        <dt>Severity</dt>
        <dd>Qualys's 1–5 rating: <span class="badge sev-critical">Critical</span> <span class="badge sev-high">High</span> <span class="badge sev-medium">Medium</span> <span class="badge sev-low">Low</span>. Informational items aren't shown.</dd>
        <dt>QID</dt>
        <dd>Qualys's ID number for one vulnerability check. One QID can cover several CVEs.</dd>
        <dt>CVE</dt>
        <dd>The public identifier for a vulnerability, such as CVE-2026-10001.</dd>
        <dt>CVSS</dt>
        <dd>An industry score from 0 to 10 for how serious a vulnerability is.</dd>
        <dt>EPSS</dt>
        <dd>The estimated chance a vulnerability will be exploited in the next 30 days.</dd>
        <dt>KEV</dt>
        <dd>The CISA Known Exploited Vulnerabilities catalogue: vulnerabilities attackers are confirmed to be using. A <em>Ransomware</em> label means it's linked to ransomware campaigns.</dd>
        <dt>CE+</dt>
        <dd>Cyber Essentials Plus. A finding fails it with a CVSS of 7.0 or above and a fix available, not patched within <?= $patchDays ?> days of the fix's release. End-of-life software always fails.</dd>
        <dt>Potential</dt>
        <dd>A finding Qualys couldn't fully confirm. Worth checking, but it may not apply.</dd>
        <dt>Agent</dt>
        <dd>The Qualys Cloud Agent, the small program on each machine that reports what's installed and missing.</dd>
    </dl>
</section>

<?php if ($show['admin-users']): ?>
<!-- ================================================================== -->
<section class="guide-section" id="admin-users">
    <h2>Manage Users <span class="badge badge-accent guide-admin-badge">Admin</span></h2>
    <p>Account menu &rarr; <strong>Manage Users</strong>.</p>
    <h3>Adding a user</h3>
    <p>Enter a username and email address, then tick the tags the account may see. Addresses with an incomplete domain ending, such as <code>.co.u</code>, are rejected so a typo can't stop the email going out. The new user is emailed a link to set their own password. Two options:</p>
    <ul>
        <li><strong>Admin account</strong> - sees everything, ignores tag scope, and gets these admin tools.</li>
        <li><strong>Can uninstall agents</strong> - lets a client account queue agent uninstalls from the Assets page. Admins always can.</li>
    </ul>
    <p>A client account sees nothing until it has at least one tag.</p>
    <h3>Managing an existing user</h3>
    <p>To find someone, type part of their username or email in the <strong>Search</strong> box above the Users table, or pick a <strong>Tag</strong> to list only the accounts that carry it (<em>No tags</em> lists client accounts that would see nothing). The two combine, and the list stays filtered after you make a change.</p>
    <p>Press <strong>Manage</strong> on a user's row to open their actions:</p>
    <ul>
        <li><strong>Email</strong> - correct their email address. Tick the box to send a password link to the new address at the same time: a setup link if they've never signed in, otherwise a reset link.</li>
        <li><strong>Access</strong> - edit tags, make or remove admin, grant or revoke agent uninstall.</li>
        <li><strong>Password</strong> - <strong>Email reset link</strong> so they choose their own, or set one for them (12+ characters).</li>
        <li><strong>MFA</strong> - <strong>Reset MFA</strong> if they've lost their authenticator, and revoke their trusted devices one at a time or all at once.</li>
        <li><strong>Account</strong> - <strong>Deactivate</strong> (blocks sign-in but keeps the account; <strong>Reactivate</strong> undoes it) or <strong>Delete</strong>.</li>
    </ul>
    <h3>Tags</h3>
    <p>Tags come from Qualys. Add a tag with its name and Qualys identifier, or leave the identifier blank to create a <em>pending</em> tag to fill in later. Set a tag's <strong>Agent activation ID</strong> to give users with that tag the <strong>Install agent</strong> button on the Assets page, pre-filled with that ID.</p>
</section>
<?php endif; ?>

<?php if ($show['org-admin']): ?>
<!-- ================================================================== -->
<section class="guide-section" id="org-admin">
    <h2>My organisation</h2>
    <p>Account menu &rarr; <strong>My organisation</strong>. As your organisation's admin you can:</p>
    <ul>
        <li><strong>Invite someone</strong> - enter their username and email. They're emailed a link to set their password (valid for 7 days) and see the same systems as everyone else in your organisation.</li>
        <li><strong>Deactivate</strong> someone who has left - they're signed out straight away and can't sign in. <strong>Reactivate</strong> brings them back.</li>
        <li><strong>Send password link</strong> - for someone who lost their invitation or forgot their password. It goes to the email address already on their account.</li>
    </ul>
    <p>Your organisation has a limit on how many active users it can have, shown at the top of the page. Deactivated people don't count towards it. To raise the limit, change which systems your organisation sees, or change another organisation admin's account, contact Plainsight.</p>
</section>
<?php endif; ?>

<?php if ($show['admin-orgs']): ?>
<!-- ================================================================== -->
<section class="guide-section" id="admin-orgs">
    <h2>Organisations <span class="badge badge-accent guide-admin-badge">Admin</span></h2>
    <p>Account menu &rarr; <strong>Organisations</strong>. An organisation groups a client's accounts and the tags they all see: every member sees the organisation's tags, plus any <em>extra tags</em> set on them individually in Manage Users. Change the organisation's tags and everyone's access changes on their next click.</p>
    <ul>
        <li><strong>User limit</strong> - the most <em>active</em> accounts the organisation can have. It stops its organisation admins inviting or reactivating past it; you can still go over it yourself. Leave blank for no limit.</li>
        <li><strong>Suspend</strong> - every member is signed out, can't sign in and gets no emails until you reactivate it.</li>
        <li><strong>Delete</strong> - members stay, without an organisation, keeping only their own extra tags.</li>
        <li><strong>Members</strong> - opens Manage Users filtered to that organisation.</li>
    </ul>
    <p>Put people in an organisation from their <strong>Manage</strong> panel on Manage Users, where you can also make them its <strong>organisation admin</strong>. Organisation admins get a <em>My organisation</em> page where they can invite people (within the limit), deactivate and reactivate them, and send password links - nothing else: no tags, roles, emails or other organisations.</p>
    <p>To add many people at once, use <strong>Import from CSV</strong> on Manage Users. Columns: <code>username</code>, <code>email</code> (required), <code>organisation</code>, <code>tags</code> (separated by <code>;</code>) and <code>org_admin</code> (yes/no). Every row is checked first; if any has a problem, nothing is created and each problem is listed.</p>
</section>
<?php endif; ?>

<?php if ($show['admin-audit']): ?>
<!-- ================================================================== -->
<section class="guide-section" id="admin-audit">
    <h2>Audit Log <span class="badge badge-accent guide-admin-badge">Admin</span></h2>
    <p>Who did what: sign-ins and failures, account security changes, admin actions, hidden findings, scan and uninstall requests, remediation edits and report exports. Filter by user, activity, date range or free text.</p>
    <div class="guide-example" inert>
        <span class="guide-example-label">Example</span>
        <div class="table-wrap">
        <table class="vuln-table">
            <thead><tr><th>When</th><th>User</th><th>Action</th><th>Target</th><th>IP address</th></tr></thead>
            <tbody>
                <tr><td class="mono">2026-11-22 09:41</td><td>jsmith</td><td>scan.requested</td><td>NW-LT-014</td><td class="mono">203.0.113.24</td></tr>
                <tr><td class="mono">2026-11-22 09:12</td><td>jsmith</td><td>auth.login</td><td>—</td><td class="mono">203.0.113.24</td></tr>
            </tbody>
        </table>
        </div>
    </div>
</section>
<?php endif; ?>

<?php if ($show['admin-api']): ?>
<!-- ================================================================== -->
<section class="guide-section" id="admin-api">
    <h2>API Usage <span class="badge badge-accent guide-admin-badge">Admin</span></h2>
    <p>Every call the dashboard has made to the Qualys API, counted per request: by API version and endpoint, hour by hour over the last 24 hours, and day by day over the last 30. Use it to check the syncs and on-demand scans are staying inside the subscription's API limits.</p>
    <p>The <strong>Forecast</strong> panel at the top projects each API version's Host Detection and Host List calls per day at the current number of assets, and roughly how many assets would fit at each sync interval. The host sync picks the shortest interval that fits by itself (shown as <em>auto</em>), and admins are emailed when it changes, when the forecast can't fit at all, or when Qualys reports 5 or fewer calls left on an endpoint.</p>
</section>
<?php endif; ?>

</div><!-- .guide-content -->
</div><!-- .guide-layout -->

<?php require __DIR__ . '/../src/views/footer.php'; ?>
