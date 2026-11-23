<?php
declare(strict_types=1);

namespace VulnDash\Lib;

/**
 * Admin-authored remediation overrides, keyed by QID (see
 * database/migrations/2026-07-add-custom-remediation.sql). When a row exists
 * for a QID, the vulnerability detail page shows this text in place of
 * Qualys's knowledge_base.solution - for every detection of that QID and every
 * account that can see it.
 *
 * The model is deliberately simple: presence of a row = override active,
 * absence = fall back to Qualys's own solution. "Reverting" is therefore just
 * deleting the row (remove()), since the Qualys text in knowledge_base.solution
 * was never modified and reappears on its own.
 *
 * content_format records how `remediation` is to be read (see
 * database/migrations/2026-10-add-custom-remediation-format.sql):
 *   - 'html' - written by the rich-text editor. Always stored already passed
 *     through Helpers::sanitizeVendorHtml(), and sanitised again on display,
 *     exactly like Qualys's own solution field.
 *   - 'text' - plain text saved before the editor existed. Shown escaped, and
 *     converted to HTML (Helpers::plainTextToHtml()) when loaded into the
 *     editor, so the next save turns it into 'html'.
 * Storing the format explicitly, rather than guessing from whether the text
 * "looks like" HTML, means a plain-text override that happens to contain
 * something like "<version 2>" can never be misread as markup.
 *
 * The detail page's single-round-trip query (VulnerabilityRepository::
 * getDetectionDetail()) still LEFT JOINs the remediation text itself; the
 * format is read through get() only when an override exists.
 */
class CustomRemediationRepository
{
    public const FORMAT_HTML = 'html';
    public const FORMAT_TEXT = 'text';

    /**
     * The override row for a QID, or null if none is set.
     *
     * @return array{qid:int, remediation:string, content_format:string, updated_by:?int, created_at:string, updated_at:string}|null
     */
    public static function get(int $qid): ?array
    {
        $stmt = Database::getConnection()->prepare(
            'SELECT qid, remediation, content_format, updated_by, created_at, updated_at
             FROM custom_remediations WHERE qid = :qid'
        );
        $stmt->execute(['qid' => $qid]);
        $row = $stmt->fetch();
        return $row ?: null;
    }

    /**
     * Creates or replaces the override for a QID. The QID must already exist in
     * knowledge_base (the fk_custom_remediation_qid foreign key enforces this) -
     * which it always will for anything reachable from a real detection, since
     * host_detections itself references knowledge_base.
     *
     * $remediation must already be sanitised HTML (Helpers::sanitizeVendorHtml())
     * - this is the only writer, and it only ever writes the 'html' format.
     *
     * $updatedBy records who last saved the text (light audit trail only).
     */
    public static function set(int $qid, string $remediation, ?int $updatedBy): void
    {
        // INSERT ... ON DUPLICATE KEY UPDATE so the first save inserts and any
        // later edit overwrites in place, keeping the original created_at while
        // updated_at/updated_by move forward.
        $stmt = Database::getConnection()->prepare(
            'INSERT INTO custom_remediations (qid, remediation, content_format, updated_by)
             VALUES (:qid, :remediation, :content_format, :updated_by)
             ON DUPLICATE KEY UPDATE
                remediation    = VALUES(remediation),
                content_format = VALUES(content_format),
                updated_by     = VALUES(updated_by)'
        );
        $stmt->execute([
            'qid'            => $qid,
            'remediation'    => $remediation,
            'content_format' => self::FORMAT_HTML,
            'updated_by'     => $updatedBy,
        ]);
    }

    /**
     * Removes the override for a QID, so the detail page falls back to Qualys's
     * own solution again. A no-op if there was no override to begin with.
     */
    public static function remove(int $qid): void
    {
        Database::getConnection()
            ->prepare('DELETE FROM custom_remediations WHERE qid = :qid')
            ->execute(['qid' => $qid]);
    }
}
