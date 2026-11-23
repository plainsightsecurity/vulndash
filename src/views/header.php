<?php
declare(strict_types=1);

/**
 * Shared header for logged-in pages. Expects $pageTitle to be set by the
 * including script. Assumes bootstrap.php has already run (session started,
 * autoloader registered).
 */

use VulnDash\Lib\Config;

$appName = Config::get('app.name') ?? 'Vulnerability Management Dashboard';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <script>
    // Applies the person's stored light/dark preference before anything
    // paints, so there's no flash of the wrong theme on load. Defaults to
    // dark (this app's original/only look) if nothing's stored yet, or if
    // localStorage isn't available at all (private browsing, etc).
    (function () {
        try {
            var stored = window.localStorage.getItem('vulndash-theme');
            document.documentElement.setAttribute('data-theme', stored === 'light' ? 'light' : 'dark');
        } catch (e) {
            document.documentElement.setAttribute('data-theme', 'dark');
        }
    })();
    </script>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="icon" href="/favicon.ico" sizes="any">
    <title><?= isset($pageTitle) ? htmlspecialchars($pageTitle) . ' — ' : '' ?><?= htmlspecialchars($appName) ?></title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="/assets/css/style.css?v=<?= @filemtime(__DIR__ . '/../../public/assets/css/style.css') ?: time() ?>">
</head>
<body>
<header class="site-header">
    <div class="site-header-inner">
        <a class="brand" href="/dashboard">
            <img class="brand-logo" src="/assets/img/nexus-logo.png?v=<?= @filemtime(__DIR__ . '/../../public/assets/img/nexus-logo.png') ?: time() ?>" alt="" aria-hidden="true">
            <?= htmlspecialchars($appName) ?>
        </a>
        <?php if (!empty($_SESSION['user_id'])): ?>
        <button type="button" class="nav-toggle" id="navToggle" aria-label="Open menu" aria-expanded="false" aria-controls="siteNav">
            <svg class="icon-menu" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><line x1="3" y1="6" x2="21" y2="6"></line><line x1="3" y1="12" x2="21" y2="12"></line><line x1="3" y1="18" x2="21" y2="18"></line></svg>
            <svg class="icon-close" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
        </button>
        <nav class="site-nav" id="siteNav">
            <a href="/dashboard">Dashboard</a>
            <a href="/trends">Trends</a>
            <a href="/ce_readiness">CE+ Readiness</a>
            <a href="/assets">Assets</a>
            <a href="/vulnerabilities">Vulnerabilities</a>
            <a href="/top_fixes">Top fixes</a>
            <a href="/reports">Reports</a>
            <?php if (!empty($_SESSION['is_admin'])): ?>
            <a href="/admin/users">Manage Users</a>
            <a href="/admin/api_usage">API Usage</a>
            <?php endif; ?>
            <!-- Account menu. The per-user, non-navigational items (Preferences,
                 Password, Security, Log out) used to sit inline in the nav row,
                 which had grown to ~11 items. Collapsing them behind the user
                 chip keeps the top-level bar to the data views (+ admin tools)
                 and reads as more finished.

                 It's a click disclosure at every width, not a hover menu: on
                 desktop the panel floats below the chip; inside the mobile
                 hamburger dropdown (see the "Mobile nav" block in style.css)
                 the same panel renders as an indented sub-list under the chip.
                 One behaviour, one bit of JS (see footer.php), works at both.
                 The chip is a real <button> so it's keyboard-focusable and
                 announces its expanded state; the theme toggle stays a
                 separate control to its right, unchanged. -->
            <!-- Search (public/search.php). An icon link rather than an inline
                 box: the nav row is already full at desktop widths. In the
                 mobile dropdown it gets a text label instead (style.css). -->
            <a href="/search" class="nav-search" aria-label="Search CVEs, QIDs, hosts" title="Search CVEs, QIDs, hosts">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="11" cy="11" r="7"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
                <span class="nav-search-label">Search</span>
            </a>
            <div class="account-menu">
                <button type="button" class="user-chip user-chip-button" id="accountMenuToggle" aria-haspopup="true" aria-expanded="false" aria-controls="accountMenu">
                    <span class="user-chip-name"><?= htmlspecialchars($_SESSION['username']) ?><?= !empty($_SESSION['is_admin']) ? ' · admin' : '' ?></span>
                    <svg class="icon-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="6 9 12 15 18 9"></polyline></svg>
                </button>
                <div class="account-menu-panel" id="accountMenu" hidden>
                    <a href="/preferences">Preferences</a>
                    <a href="/password">Password</a>
                    <a href="/mfa">Security</a>
                    <a href="/logout">Log out</a>
                </div>
            </div>
            <button type="button" class="theme-toggle" id="themeToggle" aria-label="Toggle light and dark mode" title="Toggle light and dark mode">
                <svg class="icon-sun" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="4"></circle><line x1="12" y1="2" x2="12" y2="4"></line><line x1="12" y1="20" x2="12" y2="22"></line><line x1="4.93" y1="4.93" x2="6.34" y2="6.34"></line><line x1="17.66" y1="17.66" x2="19.07" y2="19.07"></line><line x1="2" y1="12" x2="4" y2="12"></line><line x1="20" y1="12" x2="22" y2="12"></line><line x1="4.93" y1="19.07" x2="6.34" y2="17.66"></line><line x1="17.66" y1="6.34" x2="19.07" y2="4.93"></line></svg>
                <svg class="icon-moon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>
            </button>
        </nav>
        <?php endif; ?>
    </div>
</header>
<main class="site-main">
