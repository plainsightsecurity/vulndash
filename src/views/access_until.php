<?php
declare(strict_types=1);

use VulnDash\Lib\AccessExpiry;
use VulnDash\Lib\Helpers;

/**
 * A tag's access end date for display (see src/Lib/AccessExpiry.php): the
 * date, plus "Nd left" in its last 30 days or "Ended" once over. Used by the
 * CE+ Readiness tag table, the Tags drop-down label, Agent Setup and
 * Organisations, so the date reads the same everywhere. Set in the Tags table
 * on Manage Users.
 *
 * @param string|null $date tags.expires_on
 * @param string      $none what to show with no date ('' for nothing)
 */
function render_access_until(?string $date, string $none = 'No end date'): void
{
    if ($date === null || $date === '') {
        if ($none !== '') {
            echo '<span class="readiness-note">' . Helpers::e($none) . '</span>';
        }
        return;
    }
    echo '<span class="mono" title="Last day of access: ' . Helpers::e(AccessExpiry::display($date)) . '">'
        . Helpers::e(date('j M Y', (int)strtotime($date))) . '</span>';
    if (AccessExpiry::isExpired($date)) {
        echo ' <span class="badge badge-danger">Ended</span>';
    } elseif (AccessExpiry::isEnding($date)) {
        echo ' <span class="badge badge-warn">' . Helpers::e(AccessExpiry::leftLabel($date)) . '</span>';
    }
}

/**
 * The label beside a page's Tags drop-down: the access end date of the tag
 * being viewed - the selected one, or a client's only tag. Nothing on an
 * "All tags" view of several (an MSP sees each tag's date on CE+ Readiness
 * instead), or for a tag with no end date.
 *
 * @param array<int, array<string, mixed>> $availableTags the drop-down's tags
 */
function render_view_tag_access_until(array $availableTags, ?int $viewTagId): void
{
    $tag = null;
    foreach ($availableTags as $t) {
        if ($viewTagId !== null ? (int)$t['id'] === $viewTagId : count($availableTags) === 1) {
            $tag = $t;
            break;
        }
    }
    $date = $tag['expires_on'] ?? null;
    if ($date === null || $date === '') {
        return;
    }
    echo '<span class="filter-bar-access">Access until ';
    render_access_until((string)$date, '');
    echo '</span>';
}
