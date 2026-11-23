<?php
declare(strict_types=1);

require_once __DIR__ . '/../src/bootstrap.php';

use VulnDash\Lib\AuditLog;
use VulnDash\Lib\Auth;
use VulnDash\Lib\Helpers;
use VulnDash\Lib\KevAlertRepository;
use VulnDash\Lib\UserRepository;

Auth::check();

$userId  = Auth::userId();
$isAdmin = Auth::isAdmin();

// The tags this account may pick a default from - every tag for an admin, only
// their own assigned tags for a client account. Same source as the dashboard's
// "view as tag" dropdown (dashboard.php), so the two always agree on what's
// selectable.
$availableTags   = $isAdmin ? UserRepository::listTags() : UserRepository::getTagsByIds(Auth::tagIds());
$availableTagIds = array_map('intval', array_column($availableTags, 'id'));

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!Helpers::verifyCsrf($_POST['csrf_token'] ?? null)) {
        Helpers::setFlash('Your session expired - please try that again.', 'error');
        header('Location: /preferences');
        exit;
    }

    // Two independent forms post to this page; the hidden `action` field says
    // which one, so saving one preference never disturbs the other.
    $action = (string)($_POST['action'] ?? 'default_tag');

    if ($action === 'notify') {
        $freq = (string)($_POST['notify_frequency'] ?? 'off');
        if (!in_array($freq, ['off', 'daily', 'weekly'], true)) {
            Helpers::setFlash('That notification option is not valid.', 'error');
            header('Location: /preferences');
            exit;
        }

        UserRepository::setNotifyFrequency($userId, $freq);
        AuditLog::record('account.notifications_changed', ['details' => ['activity_emails' => $freq]]);

        $msg = $freq === 'off'
            ? 'Email notifications are now off.'
            : "Email notifications are now {$freq}. The emails contain no vulnerability details - just a prompt to sign in and review.";
        Helpers::setFlash($msg);
        header('Location: /preferences');
        exit;
    }

    if ($action === 'kev_alerts') {
        $enabled = !empty($_POST['kev_alerts']);
        KevAlertRepository::setEnabled($userId, $enabled);
        AuditLog::record('account.notifications_changed', ['details' => ['kev_alerts' => $enabled ? 'on' : 'off']]);
        Helpers::setFlash($enabled
            ? 'Exploited-vulnerability alerts are on. You\'ll get an email when a vulnerability on the CISA KEV list newly appears in your systems.'
            : 'Exploited-vulnerability alerts are off.');
        header('Location: /preferences');
        exit;
    }

    // --- default_tag (the original preference on this page) -------------------
    $raw = (string)($_POST['default_tag'] ?? '');
    $chosen = $raw !== '' ? (int)$raw : null;

    // Authorization check: a non-admin must not be able to pin a default tag
    // outside their own assignments by hand-posting an id. An empty value
    // ("All - no default") is always allowed. setDefaultTag() persists; this is
    // where we decide whether it's allowed to.
    if ($chosen !== null && !in_array($chosen, $availableTagIds, true)) {
        Helpers::setFlash('That tag is not one you can select.', 'error');
        header('Location: /preferences');
        exit;
    }

    UserRepository::setDefaultTag($userId, $chosen);

    // Also apply it to the current session's view filter straight away, so the
    // change is visible immediately rather than only after the next login. The
    // stored preference is what actually drives login (Auth::finalizeLogin());
    // this line is purely so "I just set my default" is reflected now too.
    if ($chosen !== null) {
        $_SESSION['view_tag_id'] = $chosen;
    } else {
        unset($_SESSION['view_tag_id']);
    }

    Helpers::setFlash('Saved. This tag will be selected each time you log in.');
    header('Location: /preferences');
    exit;
}

$currentDefault = UserRepository::getDefaultTagId($userId);
// A previously-set default that's since been deleted or un-assigned shouldn't
// show as selected (it also wouldn't apply at login - resolveViewTag() drops
// it) - treat it as "no default" in the UI so the two stay consistent.
if ($currentDefault !== null && !in_array($currentDefault, $availableTagIds, true)) {
    $currentDefault = null;
}

$currentNotify = UserRepository::getNotifyFrequency($userId);
$kevAlertsOn   = KevAlertRepository::isEnabled($userId);

$csrfToken = Helpers::csrfToken();
$flash = Helpers::getFlash();

$pageTitle = 'Preferences';
require __DIR__ . '/../src/views/header.php';
?>

<div class="page-heading">
    <h1>Preferences</h1>
    <p class="page-subtitle">Personal settings for how the dashboard opens for you.</p>
</div>

<?php if ($flash): ?>
<div class="flash flash-<?= Helpers::e($flash['type']) ?>"><?= Helpers::e($flash['message']) ?></div>
<?php endif; ?>

<div class="panel edit-panel">
    <h2>Default tag</h2>
    <p class="panel-note">
        The tag selected here is applied automatically each time you log in, so the
        dashboard, assets and vulnerabilities pages open already scoped to it. You can
        still switch to any other tag (or back to all) for the rest of a session - the
        default only re-applies at your next login.
    </p>

    <?php if (empty($availableTags)): ?>
    <p class="no-tags">You don't have any tags assigned yet, so there's nothing to set a default to. An administrator assigns tags to your account.</p>
    <?php else: ?>
    <form method="post">
        <input type="hidden" name="csrf_token" value="<?= Helpers::e($csrfToken) ?>">
        <input type="hidden" name="action" value="default_tag">
        <label class="field" style="margin-bottom: 1rem;">
            <span>Show this tag by default at login</span>
            <select name="default_tag">
                <option value="">No default (show all<?= $isAdmin ? ' tags' : ' your tags' ?>)</option>
                <?php foreach ($availableTags as $tag): ?>
                <option value="<?= (int)$tag['id'] ?>" <?= $currentDefault === (int)$tag['id'] ? 'selected' : '' ?>><?= Helpers::e($tag['name']) ?></option>
                <?php endforeach; ?>
            </select>
        </label>
        <button type="submit" class="btn btn-primary">Save preference</button>
    </form>
    <?php endif; ?>
</div>

<div class="panel edit-panel">
    <h2>Email notifications</h2>
    <p class="panel-note">
        Get an email when there's new activity on your dashboard. For your security,
        these emails never contain any vulnerability details - no asset names, findings
        or counts - only a prompt to sign in and review. Everything stays behind your
        login. Notifications are off unless you turn them on here, and you'll never get
        more than one email per period, only when there's actually something new.
    </p>

    <form method="post">
        <input type="hidden" name="csrf_token" value="<?= Helpers::e($csrfToken) ?>">
        <input type="hidden" name="action" value="notify">
        <label class="field" style="margin-bottom: 1rem;">
            <span>How often to notify me</span>
            <select name="notify_frequency">
                <option value="off"    <?= $currentNotify === 'off'    ? 'selected' : '' ?>>Off (no emails)</option>
                <option value="daily"  <?= $currentNotify === 'daily'  ? 'selected' : '' ?>>Daily &mdash; at most once a day</option>
                <option value="weekly" <?= $currentNotify === 'weekly' ? 'selected' : '' ?>>Weekly &mdash; at most once a week</option>
            </select>
        </label>
        <button type="submit" class="btn btn-primary">Save notification setting</button>
    </form>
</div>

<div class="panel edit-panel">
    <h2>Exploited-vulnerability alerts</h2>
    <p class="panel-note">
        Get an email straight away when a vulnerability that attackers are known to be
        exploiting (one on the CISA Known Exploited Vulnerabilities list) newly appears on
        <?= $isAdmin ? 'any monitored system' : 'one of your systems' ?>. These are the issues to
        patch first. Like the notifications above, the email contains no vulnerability details -
        just a link to sign in and review. Separate from the activity emails, and on by default.
    </p>

    <form method="post">
        <input type="hidden" name="csrf_token" value="<?= Helpers::e($csrfToken) ?>">
        <input type="hidden" name="action" value="kev_alerts">
        <label class="checkbox-field" style="margin-bottom: 1rem;">
            <input type="checkbox" name="kev_alerts" value="1" <?= $kevAlertsOn ? 'checked' : '' ?>>
            <span>Email me when an actively exploited vulnerability is found</span>
        </label>
        <button type="submit" class="btn btn-primary">Save alert setting</button>
    </form>
</div>

<?php require __DIR__ . '/../src/views/footer.php'; ?>
