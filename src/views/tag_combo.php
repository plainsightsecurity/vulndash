<?php
declare(strict_types=1);

use VulnDash\Lib\Helpers;

/**
 * The searchable tag picker (same markup as Manage Users' own) for pages
 * other than Manage Users - Organisations. Checkboxes named $fieldName[];
 * src/views/footer.php's shared script wires up every .tag-combo.
 *
 * @param array<int, array<string, mixed>> $tags
 * @param int[] $checked
 */
function render_tag_combo(array $tags, string $heading, array $checked, string $fieldName = 'tag_ids'): void
{
    if ($tags === []) {
        echo '<p class="no-tags">No tags exist yet - they appear here once agents report in, or add one on Manage Users.</p>';
        return;
    }
    ?>
    <div class="tag-combo">
        <button type="button" class="tag-combo-toggle" aria-expanded="false">
            <span class="tag-combo-toggle-label"><?= Helpers::e($heading) ?></span>
            <span class="tag-combo-summary"></span>
        </button>
        <div class="tag-combo-panel" hidden>
            <input type="text" class="tag-combo-search" placeholder="Filter…" aria-label="Filter <?= Helpers::e($heading) ?>">
            <div class="tag-combo-actions">
                <button type="button" class="tag-combo-selectall">Select all</button>
                <button type="button" class="tag-combo-clear">Clear</button>
            </div>
            <div class="tag-combo-list">
                <?php foreach ($tags as $tag): ?>
                <label class="tag-combo-option">
                    <input type="checkbox" name="<?= Helpers::e($fieldName) ?>[]" value="<?= (int)$tag['id'] ?>" <?= in_array((int)$tag['id'], $checked, true) ? 'checked' : '' ?>>
                    <span><?= Helpers::e($tag['name']) ?></span>
                </label>
                <?php endforeach; ?>
            </div>
            <p class="tag-combo-empty" hidden>No matches.</p>
        </div>
    </div>
    <?php
}
