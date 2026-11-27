<?php
declare(strict_types=1);

require_once __DIR__ . '/../src/bootstrap.php';

use VulnDash\Lib\Auth;
use VulnDash\Lib\CePlusDeadline;
use VulnDash\Lib\CvssCalculator;
use VulnDash\Lib\Helpers;
use VulnDash\Lib\StaleAgent;
use VulnDash\Lib\UserRepository;
use VulnDash\Lib\VulnerabilityRepository;

/*
 * "Am I affected by CVE-...?" - one box for a CVE ID, a QID, a hostname/IP or
 * a vulnerability title. Entirely local reads (kb_cve, knowledge_base,
 * host_detections, the KEV/EPSS tables): no Qualys API calls.
 *
 * A CVE or QID gets a verdict, and the verdict has three outcomes, not two:
 *   - affected: in-scope hosts have an open detection of a mapped QID;
 *   - not affected: Qualys checks for it (there are mapped QIDs) and no
 *     in-scope host has it;
 *   - can't tell: no QID maps to the CVE in the local KB cache, so the agents
 *     can't detect it at all. Reporting that as "not affected" would be the
 *     one genuinely harmful answer this page could give.
 *
 * Hidden findings are included throughout (and badged): "am I affected" is a
 * question of fact, and a hide is a display preference, not a fix.
 */

Auth::check();

$tagIds  = Auth::tagIds();
$isAdmin = Auth::isAdmin();
$userId  = Auth::userId();

$availableTags   = $isAdmin ? UserRepository::listTags() : UserRepository::getTagsByIds($tagIds);
$availableTagIds = array_map('intval', array_column($availableTags, 'id'));
$viewTagId       = Helpers::resolveViewTag($availableTagIds);

$rawQuery = trim((string)($_GET['q'] ?? ''));
$rawQuery = mb_substr($rawQuery, 0, 200);

// Classify the query. CVE accepts "CVE-2024-3094", "cve 2024-3094" and a bare
// "2024-3094"; QID accepts "12345" or "QID 12345". Anything else is a text
// search, which needs 2+ characters so a single letter doesn't match every host.
$mode = null;
$cve  = null;
$qid  = null;
if ($rawQuery !== '') {
    if (preg_match('/^(?:CVE[\s\-_]*)?(\d{4})-(\d{4,7})$/i', $rawQuery, $m)) {
        $mode = 'cve';
        $cve  = "CVE-{$m[1]}-{$m[2]}";
    } elseif (preg_match('/^(?:QID[\s:#\-]*)?(\d{1,9})$/i', $rawQuery, $m)) {
        $mode = 'qid';
        $qid  = (int)$m[1];
    } elseif (mb_strlen($rawQuery) >= 2) {
        $mode = 'text';
    } else {
        $mode = 'too_short';
    }
}

$resultLimit = 25;   // text-search cap per section
$hostLimit   = 100;  // affected-detection rows shown on a verdict

$kbEntries = [];
$intel     = ['kev' => null, 'epss' => null];
$affectedHosts = 0;
$affectedDetections = 0;
$detections = [];
$resolved = ['hosts' => 0, 'last_resolved_at' => null];
$staleCount = 0;
$hiddenAffected = 0;
$assetHits = [];
$qidHits = [];

if ($mode === 'cve' || $mode === 'qid') {
    if ($mode === 'cve') {
        $kbEntries = VulnerabilityRepository::getKbEntriesForCve($cve);
        $intel     = VulnerabilityRepository::getCveIntel($cve);
        $filters   = ['cve' => $cve];
    } else {
        $entry     = VulnerabilityRepository::getKbEntry($qid);
        $kbEntries = $entry !== null ? [$entry] : [];
        $filters   = ['qid' => $qid];
    }

    if (!empty($kbEntries)) {
        $affectedHosts      = VulnerabilityRepository::getAffectedAssetCount($tagIds, $isAdmin, $filters, $viewTagId, true, $userId);
        $affectedDetections = VulnerabilityRepository::getDetectionsCount($tagIds, $isAdmin, $filters, $viewTagId, true, $userId);
        // The vulnerability list leaves this account's hidden findings out by
        // default, so the verdict says how many it's counting that the list won't.
        $hiddenAffected     = $affectedDetections - VulnerabilityRepository::getDetectionsCount($tagIds, $isAdmin, $filters, $viewTagId, false, $userId);
        $detections         = $affectedDetections > 0
            ? VulnerabilityRepository::getDetections($tagIds, $isAdmin, $filters, 1, $hostLimit, $viewTagId, 'asset', 'asc', true, $userId)
            : [];
        $resolved           = VulnerabilityRepository::getResolvedSummary($tagIds, $isAdmin, array_column($kbEntries, 'qid'), $viewTagId);
        // Hosts whose agent has gone quiet could have it without it showing -
        // the "not affected" verdict says how many.
        $staleCount         = VulnerabilityRepository::getStaleAssetCount($tagIds, $isAdmin, $viewTagId);
    }
} elseif ($mode === 'text') {
    $assetHits = VulnerabilityRepository::searchAssets($tagIds, $isAdmin, $rawQuery, $viewTagId, $resultLimit);
    $qidHits   = VulnerabilityRepository::searchQidsByTitle($tagIds, $isAdmin, $rawQuery, $viewTagId, $resultLimit);
}
$assetCapped = count($assetHits) > $resultLimit;
$qidCapped   = count($qidHits) > $resultLimit;
$assetHits   = array_slice($assetHits, 0, $resultLimit);
$qidHits     = array_slice($qidHits, 0, $resultLimit);

$retentionDays = max(1, (int)(\VulnDash\Lib\Config::get('sync.resolution_retention_days') ?? 90));
$subject = $mode === 'cve' ? $cve : ($mode === 'qid' ? 'QID ' . $qid : null);
$listHref = $mode === 'cve' ? '/vulnerabilities?cve=' . rawurlencode((string)$cve) : ($mode === 'qid' ? '/vulnerabilities?qid=' . (int)$qid : null);

/** Effective score for a KB row, the same way detections are scored (CvssCalculator). */
$kbScore = static function (array $kb): float {
    return CvssCalculator::calculate(
        $kb['cvss3_base'] !== null ? (float)$kb['cvss3_base'] : null,
        $kb['cvss_base'] !== null ? (float)$kb['cvss_base'] : null,
        (int)$kb['severity_level'],
        (string)$kb['title']
    )['score'];
};

$pageTitle = $subject !== null ? "Search: {$subject}" : 'Search';
require __DIR__ . '/../src/views/header.php';
?>

<div class="page-heading">
    <h1>Search</h1>
    <p class="page-subtitle">Check whether you're affected by a CVE, or find a QID, host or vulnerability by name.</p>
</div>

<form method="get" action="/search" class="filter-bar search-page-form">
    <label class="field search-page-field">
        <span>CVE, QID, hostname, IP or title</span>
        <input type="search" name="q" value="<?= Helpers::e($rawQuery) ?>" placeholder="e.g. CVE-2024-3094, 38739, web01, OpenSSH" autocomplete="off" <?= $rawQuery === '' ? 'autofocus' : '' ?>>
    </label>
    <?php if (count($availableTags) > 1): ?>
    <label class="field field-inline">
        <span>Tags</span>
        <select name="view_tag">
            <option value="">All<?= $isAdmin ? ' tags' : ' your tags' ?></option>
            <?php foreach ($availableTags as $tag): ?>
            <option value="<?= (int)$tag['id'] ?>" <?= $viewTagId === (int)$tag['id'] ? 'selected' : '' ?>><?= Helpers::e($tag['name']) ?></option>
            <?php endforeach; ?>
        </select>
    </label>
    <?php endif; ?>
    <?php render_view_tag_access_until($availableTags, $viewTagId); ?>
    <button type="submit" class="btn btn-primary">Search</button>
</form>

<?php if ($mode === 'too_short'): ?>
<p class="chart-empty">Enter at least 2 characters.</p>

<?php elseif ($mode === 'cve' || $mode === 'qid'): ?>

    <?php if (empty($kbEntries)): ?>
    <div class="search-verdict search-verdict-unknown">
        <strong>Can't tell.</strong>
        <?php if ($mode === 'cve'): ?>
        Qualys has no detection (QID) for <?= Helpers::e($cve) ?> in the knowledge base, so the agents can't check for it. That doesn't mean you're unaffected. Qualys may not have published a detection yet, or the CVE may not apply to anything it scans for. Check the vendor's advisory, or search again in a day or two once the knowledge base has updated.
        <?php else: ?>
        QID <?= (int)$qid ?> isn't in the knowledge base. Check the number, or try a CVE ID or title instead.
        <?php endif; ?>
    </div>

    <?php elseif ($affectedHosts > 0): ?>
    <div class="search-verdict search-verdict-affected">
        <strong>Affected.</strong>
        <?= number_format($affectedHosts) ?> host<?= $affectedHosts === 1 ? ' has' : 's have' ?> <?= Helpers::e($subject) ?><?= $affectedDetections > $affectedHosts ? ' (' . number_format($affectedDetections) . ' findings, counting each port)' : '' ?>.
        <a href="<?= Helpers::e($listHref) ?>">Open in the vulnerability list →</a>
        <?php if ($hiddenAffected > 0): ?>
        <span class="readiness-note">Includes <?= number_format($hiddenAffected) ?> finding<?= $hiddenAffected === 1 ? '' : 's' ?> you've hidden. Hiding doesn't fix anything. The list leaves them out unless you show hidden findings.</span>
        <?php endif; ?>
    </div>

    <?php else: ?>
    <div class="search-verdict search-verdict-clear">
        <strong>Not affected.</strong>
        Qualys checks for <?= Helpers::e($subject) ?><?= count($kbEntries) > 1 ? ' with ' . count($kbEntries) . ' QIDs' : '' ?>, and none of your hosts currently has it.
        <span class="readiness-note">This covers hosts with a Qualys agent only.<?= $staleCount > 0 ? ' ' . number_format($staleCount) . ' host' . ($staleCount === 1 ? "'s agent hasn't" : "s' agents haven't") . ' reported in ' . StaleAgent::staleAfterDays() . '+ days, so a recent change on those wouldn\'t show yet.' : '' ?></span>
    </div>
    <?php endif; ?>

    <?php if ($resolved['hosts'] > 0): ?>
    <p class="search-resolved">
        Fixed on <?= number_format($resolved['hosts']) ?> host<?= $resolved['hosts'] === 1 ? '' : 's' ?> in the last <?= $retentionDays ?> days<?php if ($resolved['last_resolved_at'] !== null): ?>, most recently <?= Helpers::e(Helpers::displayQualysDateTime($resolved['last_resolved_at'], 'j M Y')) ?><?php endif; ?>.
    </p>
    <?php endif; ?>

    <?php if ($mode === 'cve' && ($intel['kev'] !== null || $intel['epss'] !== null)): ?>
    <ul class="readiness-caveats search-intel">
        <?php if ($intel['kev'] !== null): ?>
        <li>
            <span class="badge badge-kev">KEV</span>
            On the CISA Known Exploited Vulnerabilities catalogue since <?= Helpers::e((new \DateTimeImmutable((string)$intel['kev']['date_added']))->format('j M Y')) ?>, so it's being exploited in the wild<?= !empty($intel['kev']['known_ransomware']) ? ', including by ransomware groups' : '' ?>.
            <?php if (!empty($intel['kev']['vulnerability_name'])): ?><span class="readiness-note"><?= Helpers::e($intel['kev']['vulnerability_name']) ?></span><?php endif; ?>
        </li>
        <?php endif; ?>
        <?php if ($intel['epss'] !== null): ?>
        <li>
            EPSS <span title="<?= Helpers::e(Helpers::epssTooltip((float)$intel['epss']['epss'])) ?>"><?= Helpers::e(Helpers::epssPercent((float)$intel['epss']['epss'])) ?></span>: the estimated chance of exploitation in the next 30 days. Higher than <?= (int)floor((float)$intel['epss']['percentile'] * 100) ?>% of scored CVEs.
        </li>
        <?php endif; ?>
    </ul>
    <?php endif; ?>

    <?php if (!empty($kbEntries)): ?>
    <h2 class="section-heading">Qualys detection<?= count($kbEntries) === 1 ? '' : 's' ?> <span class="section-heading-sub"><?= $mode === 'cve' ? 'QIDs that check for ' . Helpers::e($cve) : 'knowledge base entry' ?></span></h2>
    <div class="table-wrap">
    <table class="vuln-table">
        <thead>
            <tr>
                <th>QID</th>
                <th>Title</th>
                <th class="col-num">CVSS</th>
                <th>Fix available</th>
                <th>Published</th>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($kbEntries as $kb): ?>
            <tr>
                <td class="mono"><a href="/search?q=<?= (int)$kb['qid'] ?>"><?= (int)$kb['qid'] ?></a></td>
                <td>
                    <?= Helpers::e($kb['title']) ?>
                    <?php if (!empty($kb['is_kev'])): ?><span class="badge badge-kev" title="On the CISA Known Exploited Vulnerabilities catalogue">KEV</span><?php endif; ?>
                </td>
                <td class="mono col-num"><?= number_format($kbScore($kb), 1) ?></td>
                <td><?= (int)$kb['patchable'] === 1 ? 'Yes' : 'No' ?></td>
                <td class="mono"><?= $kb['published_datetime'] !== null ? Helpers::e(Helpers::displayQualysDateTime($kb['published_datetime'], 'Y-m-d')) : '—' ?></td>
            </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
    </div>
    <?php if ($mode === 'qid' && !empty($kbEntries[0]['cve_ids'])): ?>
    <p class="readiness-note">CVEs: <?= Helpers::e((string)$kbEntries[0]['cve_ids']) ?></p>
    <?php endif; ?>
    <?php endif; ?>

    <?php if (!empty($detections)): ?>
    <h2 class="section-heading">Affected hosts <span class="section-heading-sub"><?= number_format($affectedDetections) ?> finding<?= $affectedDetections === 1 ? '' : 's' ?><?= $affectedDetections > count($detections) ? ' · first ' . count($detections) . ' shown' : '' ?></span></h2>
    <div class="table-wrap">
    <table class="vuln-table">
        <thead>
            <tr>
                <th>Asset</th>
                <th>QID</th>
                <th>Port</th>
                <th>Status</th>
                <th>First found</th>
                <th>CE+ due</th>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($detections as $row):
                $dl = CePlusDeadline::forRow($row);
            ?>
            <tr>
                <td>
                    <a href="/vulnerability_detail?id=<?= (int)$row['id'] ?>"><?= Helpers::e($row['hostname'] ?: $row['ip_address'] ?: 'Unknown host') ?></a>
                    <?php if (!empty($row['hidden_state'])): ?>
                    <span class="badge badge-hidden" title="Hidden from your default view, but you're still affected">Hidden</span>
                    <?php endif; ?>
                </td>
                <td class="mono"><?= (int)$row['qid'] ?></td>
                <td class="mono"><?= $row['port'] !== null ? (int)$row['port'] . ($row['protocol'] ? '/' . Helpers::e($row['protocol']) : '') : '—' ?></td>
                <td><?= Helpers::e($row['status']) ?></td>
                <td class="mono"><?= $row['first_found'] !== null ? Helpers::e(Helpers::displayQualysDateTime($row['first_found'], 'Y-m-d')) : '—' ?></td>
                <td class="mono">
                    <?php if ((int)$row['is_ce_plus_fail'] !== 1): ?>
                    <span class="readiness-note" title="Below CVSS 7.0, or a zero-day - not a CE+ failure">n/a</span>
                    <?php elseif ($dl === null): ?>
                    <span class="readiness-note" title="No vendor fix released yet">No fix</span>
                    <?php else: ?>
                    <span class="<?= $dl['overdue'] ? 'badge badge-ce-fail' : '' ?>" title="Patch <?= $dl['overdue'] ? 'was due' : 'due' ?> <?= Helpers::e($dl['due']->format('Y-m-d')) ?>"><?= Helpers::e(CePlusDeadline::shortLabel($dl)) ?></span>
                    <?php endif; ?>
                </td>
            </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
    </div>
    <?php endif; ?>

<?php elseif ($mode === 'text'): ?>

    <?php if (empty($assetHits) && empty($qidHits)): ?>
    <p class="chart-empty">Nothing matches "<?= Helpers::e($rawQuery) ?>": no host name or IP, and no open vulnerability title. To check a specific vulnerability, search by its CVE ID.</p>
    <?php endif; ?>

    <?php if (!empty($qidHits)): ?>
    <h2 class="section-heading">Vulnerabilities <span class="section-heading-sub">open findings whose title matches<?= $qidCapped ? ' · top ' . $resultLimit . ' shown' : '' ?></span></h2>
    <div class="table-wrap">
    <table class="vuln-table">
        <thead>
            <tr>
                <th>QID</th>
                <th>Title</th>
                <th class="col-num">CVSS</th>
                <th class="col-num">Hosts</th>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($qidHits as $hit): ?>
            <tr>
                <td class="mono"><a href="/search?q=<?= (int)$hit['qid'] ?>"><?= (int)$hit['qid'] ?></a></td>
                <td>
                    <a href="/search?q=<?= (int)$hit['qid'] ?>"><?= Helpers::e($hit['title']) ?></a>
                    <?php if ((int)$hit['is_ce_plus_fail'] === 1): ?><span class="badge badge-ce-fail">CE+</span><?php endif; ?>
                    <?php if ((int)$hit['is_kev'] === 1): ?><span class="badge badge-kev">KEV</span><?php endif; ?>
                </td>
                <td class="mono col-num"><?= number_format((float)$hit['cvss'], 1) ?></td>
                <td class="mono col-num"><?= number_format((int)$hit['hosts']) ?></td>
            </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
    </div>
    <?php if ($qidCapped): ?>
    <p class="readiness-note">More matches than shown. <a href="/vulnerabilities?q=<?= rawurlencode($rawQuery) ?>">See them all in the vulnerability list →</a></p>
    <?php endif; ?>
    <?php endif; ?>

    <?php if (!empty($assetHits)): ?>
    <h2 class="section-heading">Hosts <span class="section-heading-sub">hostname, DNS name or IP matches<?= $assetCapped ? ' · first ' . $resultLimit . ' shown' : '' ?></span></h2>
    <div class="table-wrap">
    <table class="vuln-table">
        <thead>
            <tr>
                <th>Host</th>
                <th>IP</th>
                <th>OS</th>
                <th class="col-num">Open findings</th>
                <th>Last scan</th>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($assetHits as $a):
                $stale = StaleAgent::status($a['last_scan_date']);
            ?>
            <tr>
                <td><a href="/vulnerabilities?asset_id=<?= (int)$a['id'] ?>"><?= Helpers::e($a['hostname'] ?: $a['ip_address'] ?: 'Unknown host') ?></a></td>
                <td class="mono"><?= Helpers::e($a['ip_address'] ?: '—') ?></td>
                <td><?= Helpers::e($a['os'] ?: '—') ?></td>
                <td class="mono col-num"><?= number_format((int)$a['open_count']) ?></td>
                <td class="mono last-scan-cell">
                    <?php if ($stale === null): ?>
                    <?= Helpers::e(Helpers::displayQualysDateTime($a['last_scan_date'], 'Y-m-d H:i')) ?>
                    <?php else: ?>
                    <span class="badge sev-medium badge-stale" title="<?= Helpers::e(StaleAgent::label($stale)) ?>"><?= Helpers::e(StaleAgent::shortLabel($stale)) ?></span>
                    <?php endif; ?>
                </td>
            </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
    </div>
    <?php if ($assetCapped): ?>
    <p class="readiness-note">More hosts match. <a href="/assets?q=<?= rawurlencode($rawQuery) ?>">See them all on the Assets page →</a></p>
    <?php endif; ?>
    <?php endif; ?>

<?php else: ?>
<ul class="readiness-caveats search-help">
    <li><strong>CVE ID</strong> (e.g. CVE-2024-3094): tells you whether any of your hosts is affected, which Qualys detections cover it, and whether it's known to be exploited.</li>
    <li><strong>QID</strong> (e.g. 38739): the same answer for a single Qualys detection.</li>
    <li><strong>Hostname, IP or title</strong> (e.g. web01, 10.0.4., OpenSSH): finds matching hosts and open vulnerabilities.</li>
</ul>
<?php endif; ?>

<?php require __DIR__ . '/../src/views/footer.php'; ?>
