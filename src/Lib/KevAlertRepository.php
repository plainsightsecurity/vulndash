<?php
declare(strict_types=1);

namespace VulnDash\Lib;

/**
 * State for the new-KEV alert emails (scripts/send_kev_alerts.php). See
 * database/migrations/2026-11-add-kev-alerts.sql for the columns and table.
 *
 * For each account with alerts on, the script compares the KEV findings in
 * its scope now (VulnerabilityRepository::getOpenKevKeys()) with the ones in
 * kev_alert_seen. Anything new means one email; then the new keys are
 * recorded so the same finding never triggers a second one. An account that
 * has never been baselined has its current KEV findings recorded silently
 * first, so switching alerts on or creating an account never sends a
 * backlog.
 *
 * Keys are "assetId:qid" strings throughout, matching getOpenKevKeys().
 */
class KevAlertRepository
{
    /**
     * Active accounts with KEV alerts on.
     *
     * @return array<int, array{id:int, username:string, email:string, is_admin:bool, baselined:bool}>
     */
    public static function recipients(): array
    {
        $rows = Database::getConnection()->query(
            "SELECT id, username, email, is_admin, kev_alert_baseline_at
             FROM users
             WHERE is_active = 1 AND kev_alerts = 1 AND email <> ''
             ORDER BY id"
        )->fetchAll();

        return array_map(static fn (array $r): array => [
            'id'        => (int)$r['id'],
            'username'  => (string)$r['username'],
            'email'     => (string)$r['email'],
            'is_admin'  => (int)$r['is_admin'] === 1,
            'baselined' => $r['kev_alert_baseline_at'] !== null,
        ], $rows);
    }

    /** @return string[] "assetId:qid" keys already alerted or baselined for this account */
    public static function seenKeys(int $userId): array
    {
        $stmt = Database::getConnection()->prepare(
            "SELECT CONCAT(asset_id, ':', qid) FROM kev_alert_seen WHERE user_id = :uid"
        );
        $stmt->execute(['uid' => $userId]);
        return $stmt->fetchAll(\PDO::FETCH_COLUMN);
    }

    /** @param string[] $keys "assetId:qid" */
    public static function markSeen(int $userId, array $keys): void
    {
        if ($keys === []) {
            return;
        }
        $stmt = Database::getConnection()->prepare(
            'INSERT IGNORE INTO kev_alert_seen (user_id, asset_id, qid, seen_at) VALUES (:uid, :asset, :qid, NOW())'
        );
        foreach ($keys as $key) {
            [$assetId, $qid] = array_map('intval', explode(':', $key, 2));
            $stmt->execute(['uid' => $userId, 'asset' => $assetId, 'qid' => $qid]);
        }
    }

    public static function markBaselined(int $userId): void
    {
        Database::getConnection()
            ->prepare('UPDATE users SET kev_alert_baseline_at = NOW() WHERE id = :id')
            ->execute(['id' => $userId]);
    }

    /**
     * Forgets (asset, QID) combinations that are no longer open anywhere -
     * fixed, or the asset gone - so a finding that comes back later alerts
     * again. Deliberately not tied to scope or hiding: a hidden finding stays
     * "seen" and unhiding it doesn't re-alert.
     *
     * @return int rows removed
     */
    public static function pruneClosed(): int
    {
        return (int)Database::getConnection()->exec(
            "DELETE s FROM kev_alert_seen s
             WHERE NOT EXISTS (
                 SELECT 1 FROM host_detections hd
                 WHERE hd.asset_id = s.asset_id AND hd.qid = s.qid
                   AND hd.status != 'Fixed' AND hd.effective_cvss_score > 0.0
             )"
        );
    }

    public static function isEnabled(int $userId): bool
    {
        $stmt = Database::getConnection()->prepare('SELECT kev_alerts FROM users WHERE id = :id');
        $stmt->execute(['id' => $userId]);
        return (int)$stmt->fetchColumn() === 1;
    }

    /**
     * Turning alerts back on clears the baseline, so the next run quietly
     * records what's already there instead of emailing about findings that
     * appeared while they were off.
     */
    public static function setEnabled(int $userId, bool $enabled): void
    {
        $pdo = Database::getConnection();
        if ($enabled) {
            $pdo->prepare('UPDATE users SET kev_alerts = 1, kev_alert_baseline_at = NULL WHERE id = :id AND kev_alerts = 0')
                ->execute(['id' => $userId]);
            $pdo->prepare('DELETE FROM kev_alert_seen WHERE user_id = :id AND (SELECT kev_alert_baseline_at FROM users WHERE id = :id2) IS NULL')
                ->execute(['id' => $userId, 'id2' => $userId]);
        } else {
            $pdo->prepare('UPDATE users SET kev_alerts = 0 WHERE id = :id')->execute(['id' => $userId]);
        }
    }
}
