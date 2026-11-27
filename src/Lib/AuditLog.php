<?php
declare(strict_types=1);

namespace VulnDash\Lib;

/**
 * Append-only record of who did what, shown to admins on
 * public/admin/audit_log.php. Table: database/migrations/2026-11-add-audit-log.sql.
 *
 * Writing is best-effort by design: record() never throws. A failed audit
 * write is logged to the PHP error log but must not stop the action being
 * audited (someone being unable to sign in because the audit insert failed
 * would be worse than a gap in the log).
 *
 * The actor defaults to the signed-in session user. Sign-in events, which
 * happen before there is a session user, pass the account explicitly. While
 * an admin is viewing as someone (Auth::startImpersonation()) the actor is
 * the admin, with details.viewing_as naming the account - so nothing an admin
 * does that way can ever read as the client having done it.
 * Usernames are copied into each row so history survives account deletion.
 *
 * Action names are "area.verb" - auth.*, account.*, admin.*, finding.*,
 * scan.*, agent.*, report.* - and ACTION_LABELS gives each a readable label
 * for the page. Never put secrets in details (passwords, tokens, MFA codes).
 */
class AuditLog
{
    public const DEFAULT_RETENTION_DAYS = 365;

    /** @var array<string, string> action => label shown on the Audit Log page */
    public const ACTION_LABELS = [
        'auth.login'                   => 'Signed in',
        'auth.login_failed'            => 'Sign-in failed',
        'auth.account_locked'          => 'Account locked (too many failed sign-ins)',
        'auth.mfa_failed'              => 'Two-factor code rejected',
        'auth.logout'                  => 'Signed out',
        'auth.session_expired'         => 'Session timed out',
        'account.password_changed'     => 'Changed own password',
        'account.password_reset_requested' => 'Requested a password reset email',
        'account.password_reset'       => 'Set password from emailed link',
        'account.mfa_enabled'          => 'Turned on two-factor',
        'account.mfa_disabled'         => 'Turned off two-factor',
        'account.trusted_device_revoked' => 'Revoked a trusted device',
        'account.trusted_devices_revoked' => 'Revoked all trusted devices',
        'account.notifications_changed' => 'Changed email notifications',
        'admin.user_created'           => 'Created account',
        'admin.user_tags_changed'      => 'Changed account tags',
        'admin.user_email_changed'     => 'Changed account email',
        'admin.user_org_changed'       => 'Changed account organisation',
        'admin.users_imported'         => 'Imported accounts from CSV',
        'admin.org_created'            => 'Created organisation',
        'admin.org_updated'            => 'Changed organisation',
        'admin.org_suspended'          => 'Suspended organisation',
        'admin.org_reactivated'        => 'Reactivated organisation',
        'admin.org_deleted'            => 'Deleted organisation',
        'org.user_invited'             => 'Org admin: invited account',
        'org.user_active_changed'      => 'Org admin: activated / deactivated account',
        'org.setup_link_sent'          => 'Org admin: sent password link',
        'admin.user_admin_changed'     => 'Changed admin status',
        'admin.user_uninstall_changed' => 'Changed agent-uninstall permission',
        'admin.user_active_changed'    => 'Activated / deactivated account',
        'admin.user_password_set'      => 'Set an account\'s password',
        'admin.password_reset_sent'    => 'Sent a password reset email',
        'admin.user_deleted'           => 'Deleted account',
        'admin.mfa_reset'              => 'Reset an account\'s two-factor',
        'admin.trusted_device_revoked' => 'Revoked an account\'s trusted device',
        'admin.trusted_devices_revoked' => 'Revoked all of an account\'s trusted devices',
        'admin.tag_created'            => 'Created tag',
        'admin.tag_deleted'            => 'Deleted tag',
        'admin.ce_assessment_date'     => 'Set CE+ assessment date',
        'admin.tag_activation_id'      => 'Set agent activation ID',
        'admin.tag_access_until'       => 'Set tag access end date',
        'admin.agent_setup'            => 'Created client agent tag and activation key',
        'admin.agent_setup_linked'     => 'Linked existing client agent tag and key',
        'admin.agent_setup_unlinked'   => 'Unlinked client agent set-up',
        'admin.agent_setup_deleted'    => 'Deleted client agent set-up (and its Qualys tag/key)',
        'admin.remediation_set'        => 'Saved custom remediation',
        'admin.remediation_reverted'   => 'Reverted custom remediation',
        'admin.impersonation_started'  => 'Started viewing as account',
        'admin.impersonation_ended'    => 'Stopped viewing as account',
        'finding.hidden'               => 'Hid a finding',
        'finding.unhidden'             => 'Unhid a finding',
        'scan.requested'               => 'Requested on-demand scan',
        'agent.uninstall_requested'    => 'Requested agent uninstall',
        'report.exported'              => 'Exported a report',
    ];

    /**
     * @param array{target_type?: string, target_id?: int|string|null, target_label?: ?string,
     *              details?: array<string, mixed>, user_id?: ?int, username?: ?string} $opts
     *        user_id/username override the actor (default: the session user).
     */
    public static function record(string $action, array $opts = []): void
    {
        try {
            $hasActor = array_key_exists('user_id', $opts) || array_key_exists('username', $opts);
            $userId   = $hasActor ? ($opts['user_id'] ?? null) : (isset($_SESSION['user_id']) ? (int)$_SESSION['user_id'] : null);
            $username = $hasActor ? ($opts['username'] ?? null) : ($_SESSION['username'] ?? null);
            $details  = $opts['details'] ?? [];

            $imp = $_SESSION['impersonator'] ?? null;
            if (!$hasActor && is_array($imp) && !empty($imp['user_id'])) {
                $details  = ['viewing_as' => $username] + $details;
                $userId   = (int)$imp['user_id'];
                $username = $imp['username'] ?? null;
            }

            $pdo = Database::getConnection();
            $pdo->prepare(
                'INSERT INTO audit_log (occurred_at, user_id, username, action, target_type, target_id, target_label, details, ip_address)
                 VALUES (NOW(), :uid, :uname, :action, :ttype, :tid, :tlabel, :details, :ip)'
            )->execute([
                'uid'     => $userId,
                'uname'   => $username !== null ? mb_substr((string)$username, 0, 255) : null,
                'action'  => $action,
                'ttype'   => $opts['target_type'] ?? null,
                'tid'     => isset($opts['target_id']) ? (string)$opts['target_id'] : null,
                'tlabel'  => isset($opts['target_label']) ? mb_substr((string)$opts['target_label'], 0, 255) : null,
                'details' => $details !== [] ? json_encode($details, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) : null,
                'ip'      => PHP_SAPI === 'cli' ? null : (LoginThrottleRepository::clientIp() ?: null),
            ]);

            // Retention without a cron job: roughly one write in 200 trims
            // anything past the retention window, in bounded batches.
            if (random_int(1, 200) === 1) {
                self::prune();
            }
        } catch (\Throwable $e) {
            error_log('AuditLog: could not record "' . $action . '": ' . $e->getMessage());
        }
    }

    public static function retentionDays(): int
    {
        $days = (int)(Config::get('audit.retention_days') ?? self::DEFAULT_RETENTION_DAYS);
        return $days > 0 ? $days : self::DEFAULT_RETENTION_DAYS;
    }

    /** @return int rows removed */
    public static function prune(): int
    {
        $stmt = Database::getConnection()->prepare(
            'DELETE FROM audit_log WHERE occurred_at < NOW() - INTERVAL :days DAY LIMIT 5000'
        );
        $stmt->execute(['days' => self::retentionDays()]);
        return $stmt->rowCount();
    }

    public static function label(string $action): string
    {
        return self::ACTION_LABELS[$action] ?? $action;
    }

    /**
     * @param array{user?: ?string, area?: ?string, action?: ?string, from?: ?string, to?: ?string, q?: ?string} $filters
     *        from/to are Y-m-d (inclusive), area is the part before the dot.
     * @return array{0: string, 1: array<string, mixed>} [WHERE sql, params]
     */
    private static function where(array $filters): array
    {
        $where = ['1 = 1'];
        $params = [];
        if (!empty($filters['user'])) {
            $where[] = 'username = :user';
            $params['user'] = $filters['user'];
        }
        if (!empty($filters['action'])) {
            $where[] = 'action = :action';
            $params['action'] = $filters['action'];
        } elseif (!empty($filters['area'])) {
            $where[] = 'action LIKE :area';
            $params['area'] = $filters['area'] . '.%';
        }
        if (!empty($filters['from'])) {
            $where[] = 'occurred_at >= :from';
            $params['from'] = $filters['from'] . ' 00:00:00';
        }
        if (!empty($filters['to'])) {
            $where[] = 'occurred_at < :to + INTERVAL 1 DAY';
            $params['to'] = $filters['to'];
        }
        if (!empty($filters['q'])) {
            // Distinct placeholder per use - non-emulated prepares.
            $where[] = '(target_label LIKE :q1 OR target_id = :q2 OR ip_address = :q3 OR CAST(details AS CHAR) LIKE :q4)';
            $like = '%' . addcslashes((string)$filters['q'], '%_\\') . '%';
            $params += ['q1' => $like, 'q2' => $filters['q'], 'q3' => $filters['q'], 'q4' => $like];
        }
        return [implode(' AND ', $where), $params];
    }

    public static function count(array $filters): int
    {
        [$where, $params] = self::where($filters);
        $stmt = Database::getConnection()->prepare("SELECT COUNT(*) FROM audit_log WHERE $where");
        $stmt->execute($params);
        return (int)$stmt->fetchColumn();
    }

    /** @return array<int, array<string, mixed>> newest first, details decoded */
    public static function search(array $filters, int $limit = 50, int $offset = 0): array
    {
        [$where, $params] = self::where($filters);
        $limit = max(1, min(100000, $limit));
        $offset = max(0, $offset);
        $stmt = Database::getConnection()->prepare(
            "SELECT id, occurred_at, user_id, username, action, target_type, target_id, target_label, details, ip_address
             FROM audit_log WHERE $where ORDER BY occurred_at DESC, id DESC LIMIT $limit OFFSET $offset"
        );
        $stmt->execute($params);
        $rows = $stmt->fetchAll();
        foreach ($rows as &$r) {
            $r['details'] = $r['details'] !== null ? (json_decode((string)$r['details'], true) ?: []) : [];
        }
        return $rows;
    }

    /** @return string[] usernames that appear as actors, for the filter dropdown */
    public static function actors(): array
    {
        return Database::getConnection()
            ->query('SELECT DISTINCT username FROM audit_log WHERE username IS NOT NULL ORDER BY username')
            ->fetchAll(\PDO::FETCH_COLUMN);
    }
}
