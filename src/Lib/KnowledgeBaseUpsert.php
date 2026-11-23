<?php
declare(strict_types=1);

namespace VulnDash\Lib;

/**
 * The knowledge_base upsert, for one row as QualysApiClient::
 * parseKnowledgeBaseFile() yields it.
 *
 * Added 2026-11 for scripts/fetch_missing_kb_qids.php rather than writing a
 * fourth copy of the same statement. sync_knowledge_base.php,
 * diagnose_kb.php and reconcile_kb_by_id.php still carry their own
 * identical copies; moving them onto this is a worthwhile follow-up, not
 * done here to keep the change that introduced it small. Until then, a key
 * added to parseKnowledgeBaseFile() must be added here AND in those three.
 */
final class KnowledgeBaseUpsert
{
    public static function prepare(\PDO $pdo): \PDOStatement
    {
        return $pdo->prepare('
            INSERT INTO knowledge_base
                (qid, title, severity_level, category, cvss_base, cvss_vector, cvss3_base, cvss3_vector,
                 cve_ids, vendor_reference, patchable, pci_flag, diagnosis, consequence, solution,
                 published_datetime, patch_published_date, qualys_last_modified)
            VALUES
                (:qid, :title, :severity_level, :category, :cvss_base, :cvss_vector, :cvss3_base, :cvss3_vector,
                 :cve_ids, :vendor_reference, :patchable, :pci_flag, :diagnosis, :consequence, :solution,
                 :published_datetime, :patch_published_date, :qualys_last_modified)
            ON DUPLICATE KEY UPDATE
                title = VALUES(title), severity_level = VALUES(severity_level), category = VALUES(category),
                cvss_base = VALUES(cvss_base), cvss_vector = VALUES(cvss_vector),
                cvss3_base = VALUES(cvss3_base), cvss3_vector = VALUES(cvss3_vector),
                cve_ids = VALUES(cve_ids), vendor_reference = VALUES(vendor_reference),
                patchable = VALUES(patchable), pci_flag = VALUES(pci_flag),
                diagnosis = VALUES(diagnosis), consequence = VALUES(consequence), solution = VALUES(solution),
                published_datetime = VALUES(published_datetime), patch_published_date = VALUES(patch_published_date),
                qualys_last_modified = VALUES(qualys_last_modified)
        ');
    }
}
