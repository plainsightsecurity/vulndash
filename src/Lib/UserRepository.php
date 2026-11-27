<?php
declare(strict_types=1);

namespace VulnDash\Lib;

/**
 * Admin-only user and tag management - creating accounts, assigning tag
 * scope, resetting passwords, and the small amount of manual tag
 * bookkeeping needed until the Qualys tag sync exists (see
 * scripts/lib/QualysApiClient.php). Used by public/admin/users.php.
 */
class UserRepository
{
    /**
     * trusted_device_count is a correlated subquery rather than a third
     * JOIN+GROUP_CONCAT here deliberately - joining user_trusted_devices
     * alongside user_tags/tags would fan out exactly the way
     * VulnerabilityRepository::buildTagScopeJoin()'s docblock describes,
     * inflating tag_names' GROUP_CONCAT with duplicate entries per device.
     * A correlated subquery costs one extra index lookup per row instead,
     * which is trivial at the scale of an admin user list.
     *
     * @return array<int, array<string, mixed>>
     */
    /**
     * Manage Users column sorts: key => [ORDER BY expression, flip]. "flip"
     * reverses the direction so "ascending" reads naturally on screen -
     * Role ascending is Admin before Client, MFA ascending is Enabled first.
     * Everything ties on username. This whitelist is what protects the
     * query; the page only passes the key through.
     */
    public const USER_SORT_COLUMNS = [
        'username'   => ['u.username', false],
        'email'      => ['u.email', false],
        'role'       => ['u.is_admin', true],
        'tags'       => ['tag_names', false],
        'mfa'        => ['u.mfa_enabled', true],
        'organisation' => ['organisation_name', false],
        'last_login' => ['u.last_login_at', false],
    ];

    /**
     * Every (user_id, tag_id) an account can see (2026-11 organisations): its
     * own user_tags - the optional per-user extras - plus every tag of its
     * organisation while that organisation is active. Use this, never
     * user_tags alone, for anything that decides access or recipients;
     * user_tags on its own is only "extras set on this account".
     */
    public const EFFECTIVE_TAGS_SQL = '(SELECT ut_e.user_id, ut_e.tag_id FROM user_tags ut_e
        UNION SELECT u_e.id, ot_e.tag_id FROM users u_e
            JOIN organisations o_e ON o_e.id = u_e.organisation_id AND o_e.is_active = 1
            JOIN organisation_tags ot_e ON ot_e.organisation_id = o_e.id)';

    /**
     * EFFECTIVE_TAGS_SQL minus tags whose access end date has passed
     * (AccessExpiry) - what an account can actually SEE. Used for the
     * session's scope and for emails; EFFECTIVE_TAGS_SQL itself stays the
     * "what is assigned" view for the admin pages.
     */
    public const LIVE_TAGS_SQL = '(SELECT e_l.user_id, e_l.tag_id FROM ' . self::EFFECTIVE_TAGS_SQL . ' e_l
        JOIN tags t_l ON t_l.id = e_l.tag_id WHERE (t_l.expires_on IS NULL OR t_l.expires_on >= CURDATE()))';

    /**
     * WHERE condition (on an unaliased users table) for "not in a suspended
     * organisation". A suspended organisation's members can't sign in, are
     * signed out on their next request and get no emails.
     */
    public const ORG_ACTIVE_CONDITION = '(organisation_id IS NULL OR organisation_id IN (SELECT o_a.id FROM organisations o_a WHERE o_a.is_active = 1))';

    /** Filter value for listUsers()'s $tagFilter: accounts with no tags at all. */
    public const TAG_FILTER_NONE = 'none';

    /**
     * Every account, or (admin Manage Users filter, 2026-11) only those
     * matching $search - a case-insensitive substring of the username or
     * email - and/or carrying the tag $tagFilter (a tag id, or
     * TAG_FILTER_NONE for accounts with no tags). The tag filter is an
     * EXISTS rather than a WHERE on the join, so a matching account still
     * shows ALL its tags in tag_names, not just the one filtered on.
     *
     * @param int|string|null $tagFilter
     */
    public static function listUsers(?string $search = null, int|string|null $tagFilter = null, ?string $sort = null, string $dir = 'asc', int|string|null $orgFilter = null): array
    {
        [$sortExpr, $flip] = self::USER_SORT_COLUMNS[$sort ?? 'username'] ?? self::USER_SORT_COLUMNS['username'];
        $descending = (strtolower($dir) === 'desc') !== $flip;
        // Accounts with no tags / never signed in go last in either direction.
        $nullsLast = in_array($sortExpr, ['tag_names', 'u.last_login_at', 'organisation_name'], true) ? "{$sortExpr} IS NULL, " : '';
        $orderBy = $nullsLast . $sortExpr . ($descending ? ' DESC' : ' ASC') . ($sortExpr !== 'u.username' ? ', u.username ASC' : '');

        $where = [];
        $params = [];
        if ($search !== null && $search !== '') {
            // Named placeholders can't repeat with emulated prepares off.
            $like = '%' . addcslashes($search, '%_\\') . '%';
            $where[] = '(u.username LIKE :q_username OR u.email LIKE :q_email)';
            $params['q_username'] = $like;
            $params['q_email'] = $like;
        }
        // Tag filters match what the account can SEE (its own extras plus its
        // organisation's tags), so "No tags" really means "sees nothing".
        if ($tagFilter === self::TAG_FILTER_NONE) {
            $where[] = 'NOT EXISTS (SELECT 1 FROM ' . self::EFFECTIVE_TAGS_SQL . ' fut WHERE fut.user_id = u.id)';
        } elseif (is_int($tagFilter)) {
            $where[] = 'EXISTS (SELECT 1 FROM ' . self::EFFECTIVE_TAGS_SQL . ' fut WHERE fut.user_id = u.id AND fut.tag_id = :tag_id)';
            $params['tag_id'] = $tagFilter;
        }
        if ($orgFilter === self::TAG_FILTER_NONE) {
            $where[] = 'u.organisation_id IS NULL';
        } elseif (is_int($orgFilter)) {
            $where[] = 'u.organisation_id = :org_id';
            $params['org_id'] = $orgFilter;
        }

        $stmt = Database::getConnection()->prepare("
            SELECT u.id, u.username, u.email, u.is_admin, u.can_uninstall_agents, u.is_active, u.mfa_enabled, u.last_login_at,
                   u.organisation_id, u.is_org_admin,
                   (SELECT o.name FROM organisations o WHERE o.id = u.organisation_id) AS organisation_name,
                   (SELECT o.is_active FROM organisations o WHERE o.id = u.organisation_id) AS organisation_active,
                   GROUP_CONCAT(t.name ORDER BY t.name SEPARATOR ', ') AS tag_names,
                   (SELECT COUNT(*) FROM user_trusted_devices td
                    WHERE td.user_id = u.id AND td.revoked_at IS NULL AND td.expires_at > NOW()) AS trusted_device_count
            FROM users u
            LEFT JOIN user_tags ut ON ut.user_id = u.id
            LEFT JOIN tags t ON t.id = ut.tag_id
            " . ($where !== [] ? 'WHERE ' . implode(' AND ', $where) : '') . "
            GROUP BY u.id
            ORDER BY {$orderBy}
        ");
        $stmt->execute($params);
        return $stmt->fetchAll();
    }

    public static function countUsers(): int
    {
        return (int)Database::getConnection()->query('SELECT COUNT(*) FROM users')->fetchColumn();
    }

    public static function getUser(int $id): ?array
    {
        $pdo = Database::getConnection();
        $stmt = $pdo->prepare(
            'SELECT id, username, email, is_admin, is_active, mfa_enabled, mfa_confirmed_at, last_login_at,
                    organisation_id, is_org_admin
             FROM users WHERE id = :id'
        );
        $stmt->execute(['id' => $id]);
        $user = $stmt->fetch();
        return $user ?: null;
    }

    /**
     * Looks up an account by username OR email in one query - used by the
     * public "forgot password" flow, where the person might not remember
     * which one they originally signed in with. Returns is_active too so
     * the caller can decide whether to actually send anything; either way
     * public/forgot_password.php always shows the same generic "if an
     * account exists..." message, so a stolen glance at the response can't
     * be used to test which usernames/emails are registered.
     */
    public static function findByUsernameOrEmail(string $identifier): ?array
    {
        // Two distinct placeholders bound to the same value, not the same
        // :identifier twice - Database.php disables emulated prepares
        // (real server-side statements), and MySQL/MariaDB's native
        // prepared statement protocol doesn't allow one named placeholder
        // to appear more than once in a single query.
        $stmt = Database::getConnection()->prepare(
            'SELECT id, username, email, (is_active = 1 AND ' . self::ORG_ACTIVE_CONDITION . ') AS is_active FROM users
             WHERE username = :identifier1 OR email = :identifier2 LIMIT 1'
        );
        $stmt->execute(['identifier1' => $identifier, 'identifier2' => $identifier]);
        $user = $stmt->fetch();
        return $user ?: null;
    }

    /**
     * Re-checks a password for an already-logged-in account - used to
     * gate high-trust self-service actions (currently: turning off MFA on
     * public/mfa.php) behind proving you still know the password, rather
     * than a bare click being enough for something a hijacked/left-open
     * session could otherwise do silently.
     */
    public static function checkPassword(int $userId, string $password): bool
    {
        $stmt = Database::getConnection()->prepare('SELECT password_hash FROM users WHERE id = :id');
        $stmt->execute(['id' => $userId]);
        $row = $stmt->fetch();
        return $row && password_verify($password, $row['password_hash']);
    }

    /**
     * Every tag the account can see: its own extras plus its active
     * organisation's tags. What notifications, KEV alerts and sign-in use.
     *
     * @return int[]
     */
    public static function getEffectiveTagIds(int $userId): array
    {
        $stmt = Database::getConnection()->prepare('SELECT DISTINCT tag_id FROM ' . self::LIVE_TAGS_SQL . ' e WHERE e.user_id = :id');
        $stmt->execute(['id' => $userId]);
        return array_map('intval', array_column($stmt->fetchAll(), 'tag_id'));
    }

    /**
     * Assigns (or clears, with null) an account's organisation, and whether
     * it's that organisation's admin. An account with no organisation can't
     * be an organisation admin.
     */
    public static function setOrganisation(int $userId, ?int $organisationId, bool $isOrgAdmin): void
    {
        Database::getConnection()->prepare('UPDATE users SET organisation_id = :org, is_org_admin = :oa WHERE id = :id')
            ->execute(['org' => $organisationId, 'oa' => $organisationId !== null && $isOrgAdmin ? 1 : 0, 'id' => $userId]);
    }

    /**
     * The account's OWN tags - the per-user extras set on it in Manage Users,
     * not including its organisation's. Use getEffectiveTagIds() for access.
     *
     * @return int[]
     */
    public static function getUserTagIds(int $userId): array
    {
        $pdo = Database::getConnection();
        $stmt = $pdo->prepare('SELECT tag_id FROM user_tags WHERE user_id = :id');
        $stmt->execute(['id' => $userId]);
        return array_map('intval', array_column($stmt->fetchAll(), 'tag_id'));
    }

    /**
     * The account's saved "land on this tag at login" preference, or null for
     * "no default" (start on All tags). Read by Auth::finalizeLogin() to seed
     * the per-session view-tag filter. Note this returns whatever is stored;
     * it does NOT re-check the tag against the account's current assignments -
     * that validation lives in Helpers::resolveViewTag(), which every page
     * runs anyway, so a stale value here can never actually widen scope.
     */
    public static function getDefaultTagId(int $userId): ?int
    {
        $stmt = Database::getConnection()->prepare('SELECT default_tag_id FROM users WHERE id = :id');
        $stmt->execute(['id' => $userId]);
        $value = $stmt->fetchColumn();
        return $value !== false && $value !== null ? (int)$value : null;
    }

    /**
     * The account's current session-invalidation epoch, or null if the account
     * doesn't exist. Auth::finalizeLogin() snapshots this into the session at
     * login and Auth::check() re-reads it on every request to decide whether
     * the session is still valid; resetPassword() below increments it to
     * invalidate every session that predates a password change. A null return
     * (row gone) is treated by check() as "session no longer valid".
     */
    public static function getSessionEpoch(int $userId): ?int
    {
        $stmt = Database::getConnection()->prepare('SELECT session_epoch FROM users WHERE id = :id');
        $stmt->execute(['id' => $userId]);
        $value = $stmt->fetchColumn();
        return $value !== false ? (int)$value : null;
    }

    /**
     * Everything Auth::check() re-reads on every request, in one query: the
     * session epoch it always checked, plus the account's CURRENT access -
     * active flag, admin flag, uninstall grant and tag ids.
     *
     * Added 2026-11 to close a gap: those used to be copied into the session
     * once, at login, and trusted from then on. Removing a tag from a client,
     * demoting an admin or deactivating an account therefore only took
     * effect at that person's next login - until then they kept their old
     * access, including to a tenant just taken away from them. Re-read here
     * instead, a change applies on their very next request. Replaces the
     * epoch-only lookup check() made before, so it costs no extra query.
     *
     * u.id is the primary key, so grouping by it alone is valid under
     * ONLY_FULL_GROUP_BY (the other users columns depend on it).
     *
     * Organisations (2026-11): tag_ids are the EFFECTIVE tags (own extras
     * plus the active organisation's), and an account in a suspended
     * organisation comes back is_active = false, so check() signs it out.
     *
     * @return array{session_epoch: int, is_active: bool, is_admin: bool, can_uninstall: bool, tag_ids: int[],
     *               organisation_id: ?int, is_org_admin: bool}|null
     *         null if the account no longer exists
     */
    public static function getSessionAccount(int $userId): ?array
    {
        $stmt = Database::getConnection()->prepare(
            'SELECT u.session_epoch, u.is_active, u.is_admin, u.can_uninstall_agents, u.organisation_id, u.is_org_admin,
                    (u.organisation_id IS NULL OR o.is_active = 1) AS org_active,
                    GROUP_CONCAT(DISTINCT e.tag_id) AS tag_ids
             FROM users u
             LEFT JOIN organisations o ON o.id = u.organisation_id
             LEFT JOIN ' . self::LIVE_TAGS_SQL . ' e ON e.user_id = u.id
             WHERE u.id = :id
             GROUP BY u.id, o.is_active'
        );
        $stmt->execute(['id' => $userId]);
        $row = $stmt->fetch();
        if (!$row) {
            return null;
        }
        return [
            'session_epoch' => (int)$row['session_epoch'],
            'is_active'     => (int)$row['is_active'] === 1 && (int)$row['org_active'] === 1,
            'organisation_id' => $row['organisation_id'] !== null ? (int)$row['organisation_id'] : null,
            'is_org_admin'  => (int)$row['is_org_admin'] === 1 && $row['organisation_id'] !== null,
            'is_admin'      => (int)$row['is_admin'] === 1,
            'can_uninstall' => (int)$row['can_uninstall_agents'] === 1,
            'tag_ids'       => $row['tag_ids'] !== null && $row['tag_ids'] !== ''
                ? array_map('intval', explode(',', (string)$row['tag_ids']))
                : [],
        ];
    }

    /**
     * Fresh read of whether this account may request agent uninstalls. Used
     * both to seed the session at login (Auth::finalizeLogin) and, crucially,
     * as the authoritative re-check at the moment an uninstall is actually
     * queued (public/assets.php) - so revoking the grant takes effect on the
     * client's very next action, not only after they log in again.
     */
    public static function getCanUninstall(int $userId): bool
    {
        $stmt = Database::getConnection()->prepare('SELECT can_uninstall_agents FROM users WHERE id = :id');
        $stmt->execute(['id' => $userId]);
        return (bool)$stmt->fetchColumn();
    }

    /**
     * Sets (or clears, with null) the account's default-tag preference.
     *
     * Callers are expected to have already confirmed $tagId is one the account
     * may actually see (see public/preferences.php) - this is the persistence
     * step, not the authorization check. The fk_users_default_tag foreign key
     * is a backstop: a $tagId that doesn't exist in `tags` is rejected by the
     * database rather than stored.
     */
    public static function setDefaultTag(int $userId, ?int $tagId): void
    {
        Database::getConnection()
            ->prepare('UPDATE users SET default_tag_id = :tag WHERE id = :id')
            ->execute(['tag' => $tagId, 'id' => $userId]);
    }

    /**
     * The account's opt-in email-notification cadence: 'off' (the default -
     * nobody is enrolled without choosing), 'daily' or 'weekly'. Read by
     * public/preferences.php to show the current selection. See
     * database/migrations/2026-07-add-notification-preferences.sql.
     */
    public static function getNotifyFrequency(int $userId): string
    {
        $stmt = Database::getConnection()->prepare('SELECT notify_frequency FROM users WHERE id = :id');
        $stmt->execute(['id' => $userId]);
        $value = $stmt->fetchColumn();
        return $value !== false && $value !== null ? (string)$value : 'off';
    }

    /**
     * Sets the account's notification cadence, and - crucially - seeds the
     * "new activity" watermark on any transition OUT of 'off' into daily/weekly.
     *
     * The watermark is set to the current maximum host_detections.id at the
     * moment of opting in, so a newly-subscribed account is only ever nudged
     * about findings that land AFTER it opted in - never blasted about the
     * entire pre-existing backlog as though it were new. Switching between
     * daily and weekly (both already "on") leaves the watermark alone, so an
     * account that stays continuously subscribed doesn't silently reset what
     * it's already been told about. Turning notifications 'off' leaves the
     * stored watermark untouched (harmless; it's simply re-seeded next time
     * they opt back in, so time spent switched off doesn't later arrive as a
     * flood of "new" items).
     *
     * The seed uses a correlated subquery over host_detections inside the same
     * UPDATE, so there's no separate round trip and no cross-repository call.
     * Reading the previous value first and only then updating is a benign,
     * single-user race (an account editing its own preference) - not worth a
     * locking transaction.
     *
     * Callers are expected to have validated $frequency; this also guards.
     *
     * @throws \InvalidArgumentException on an unknown frequency value
     */
    public static function setNotifyFrequency(int $userId, string $frequency): void
    {
        if (!in_array($frequency, ['off', 'daily', 'weekly'], true)) {
            throw new \InvalidArgumentException("Unknown notify frequency: {$frequency}");
        }

        $pdo = Database::getConnection();
        $previous = self::getNotifyFrequency($userId);
        $seeding  = ($previous === 'off' && $frequency !== 'off') ? 1 : 0;

        // notify_watermark_id is only rewritten when $seeding = 1 (an off->on
        // transition); otherwise it's left as-is. Named placeholders are all
        // single-use, as required under non-emulated prepares.
        $pdo->prepare(
            'UPDATE users
                SET notify_frequency = :freq,
                    notify_watermark_id = CASE
                        WHEN :seed = 1 THEN (SELECT COALESCE(MAX(id), 0) FROM host_detections)
                        ELSE notify_watermark_id
                    END
              WHERE id = :id'
        )->execute(['freq' => $frequency, 'seed' => $seeding, 'id' => $userId]);
    }

    /**
     * Includes user_count/asset_count alongside each tag so the admin UI
     * can warn with real numbers before a delete, rather than a generic
     * "are you sure?".
     *
     * Used to also classify each tag as 'agent' or 'scan' (see the former
     * tagTypeJoinSql(), removed 2026-07 when this became an agent-only
     * internal tool) - with every asset now agent-tracked by construction
     * (scripts/lib/QualysApiClient.php's agent scope filter), that split
     * no longer means anything, so this just returns tags now.
     *
     * @return array<int, array<string, mixed>>
     */
    public static function listTags(): array
    {
        $pdo = Database::getConnection();
        return $pdo->query("
            SELECT t.id, t.qualys_tag_id, t.name, t.agent_activation_id, t.expires_on,
                   COUNT(DISTINCT ut.user_id) AS user_count,
                   COUNT(DISTINCT at.asset_id) AS asset_count
            FROM tags t
            LEFT JOIN user_tags ut ON ut.tag_id = t.id
            LEFT JOIN asset_tags at ON at.tag_id = t.id
            GROUP BY t.id, t.qualys_tag_id, t.name, t.agent_activation_id, t.expires_on
            ORDER BY t.name
        ")->fetchAll();
    }

    /**
     * Same shape as listTags() (minus the user/asset counts), but
     * restricted to a specific set of local tag table IDs - used to build
     * the "view as tag" filter dropdown for a non-admin account, which
     * should only ever offer their own assigned tags rather than every tag
     * in the system.
     *
     * @param int[] $ids local tag table IDs
     * @return array<int, array<string, mixed>>
     */
    public static function getTagsByIds(array $ids): array
    {
        $ids = array_values(array_unique(array_map('intval', $ids)));
        if (empty($ids)) {
            return [];
        }

        $pdo = Database::getConnection();
        $placeholders = implode(',', array_fill(0, count($ids), '?'));
        $stmt = $pdo->prepare("
            SELECT t.id, t.qualys_tag_id, t.name, t.agent_activation_id, t.expires_on
            FROM tags t
            WHERE t.id IN ($placeholders)
            ORDER BY t.name
        ");
        $stmt->execute($ids);
        return $stmt->fetchAll();
    }

    /**
     * Creates the account with an unusable, random, never-surfaced
     * password - the person sets their own via the emailed "set your
     * password" link instead (public/admin/users.php generates the token
     * and sends it right after this returns; see PasswordResetRepository
     * and Mailer::sendPasswordSetupEmail()). Nobody ever knows this
     * placeholder value, so it functions the same as the account having
     * no password at all until the link is used, without needing
     * password_hash to allow a NULL/empty value.
     *
     * @param int[] $tagIds local tag table IDs (not Qualys tag IDs)
     * @throws \RuntimeException on duplicate username/email
     */
    public static function createUser(string $username, string $email, bool $isAdmin, array $tagIds, bool $canUninstall = false, ?int $organisationId = null, bool $isOrgAdmin = false): int
    {
        $pdo = Database::getConnection();
        $pdo->beginTransaction();
        try {
            // $canUninstall is an optional trailing param specifically so the
            // existing four-argument callers (notably scripts/create_account.php,
            // deliberately left on its old signature) keep working unchanged and
            // default to "cannot uninstall" - the fail-closed default.
            $stmt = $pdo->prepare(
                'INSERT INTO users (username, email, password_hash, is_admin, can_uninstall_agents)
                 VALUES (:username, :email, :hash, :is_admin, :can_uninstall)'
            );
            $stmt->execute([
                'username'      => $username,
                'email'         => $email,
                'hash'          => password_hash(bin2hex(random_bytes(32)), PASSWORD_BCRYPT),
                'is_admin'      => $isAdmin ? 1 : 0,
                'can_uninstall' => $canUninstall ? 1 : 0,
            ]);
            $userId = (int)$pdo->lastInsertId();

            self::syncUserTags($pdo, $userId, $tagIds);
            if ($organisationId !== null) {
                $pdo->prepare('UPDATE users SET organisation_id = :org, is_org_admin = :oa WHERE id = :id')
                    ->execute(['org' => $organisationId, 'oa' => $isOrgAdmin ? 1 : 0, 'id' => $userId]);
            }

            $pdo->commit();
            return $userId;
        } catch (\PDOException $e) {
            $pdo->rollBack();
            if ((int)$e->getCode() === 23000 || str_contains($e->getMessage(), 'Duplicate entry')) {
                throw new \RuntimeException('That username or email is already in use.');
            }
            throw $e;
        }
    }

    /**
     * Changes an account's email address (admin Manage Users). Validation of
     * the address itself is the caller's job (Helpers::emailError()); this
     * only enforces uniqueness, the same way createUser() does.
     *
     * Outstanding password setup/reset links are left alone: they're bound
     * to the account, not the address, and anyone holding one already had
     * it emailed to them.
     *
     * @throws \RuntimeException if another account already uses the address
     */
    public static function updateEmail(int $userId, string $email): void
    {
        try {
            Database::getConnection()
                ->prepare('UPDATE users SET email = :email WHERE id = :id')
                ->execute(['email' => $email, 'id' => $userId]);
        } catch (\PDOException $e) {
            if ((int)$e->getCode() === 23000 || str_contains($e->getMessage(), 'Duplicate entry')) {
                throw new \RuntimeException('That email address is already used by another account.');
            }
            throw $e;
        }
    }

    /** @param int[] $tagIds */
    public static function updateUserTags(int $userId, array $tagIds): void
    {
        $pdo = Database::getConnection();
        $pdo->beginTransaction();
        try {
            self::syncUserTags($pdo, $userId, $tagIds);
            $pdo->commit();
        } catch (\Throwable $e) {
            $pdo->rollBack();
            throw $e;
        }
    }

    /** @param int[] $tagIds */
    private static function syncUserTags(\PDO $pdo, int $userId, array $tagIds): void
    {
        $pdo->prepare('DELETE FROM user_tags WHERE user_id = :id')->execute(['id' => $userId]);

        $insert = $pdo->prepare('INSERT IGNORE INTO user_tags (user_id, tag_id) VALUES (:user_id, :tag_id)');
        foreach ($tagIds as $tagId) {
            $insert->execute(['user_id' => $userId, 'tag_id' => (int)$tagId]);
        }
    }

    public static function setAdmin(int $userId, bool $isAdmin): void
    {
        Database::getConnection()
            ->prepare('UPDATE users SET is_admin = :v WHERE id = :id')
            ->execute(['v' => $isAdmin ? 1 : 0, 'id' => $userId]);
    }

    public static function setCanUninstall(int $userId, bool $canUninstall): void
    {
        Database::getConnection()
            ->prepare('UPDATE users SET can_uninstall_agents = :v WHERE id = :id')
            ->execute(['v' => $canUninstall ? 1 : 0, 'id' => $userId]);
    }

    public static function setActive(int $userId, bool $isActive): void
    {
        Database::getConnection()
            ->prepare('UPDATE users SET is_active = :v WHERE id = :id')
            ->execute(['v' => $isActive ? 1 : 0, 'id' => $userId]);
    }

    /**
     * Sets a new password hash and, in the same statement, increments
     * session_epoch so that EVERY currently-open session for this account
     * becomes invalid (Auth::check() compares each session's stored epoch to
     * this column on the next request). This applies to all three callers -
     * self-service change (public/password.php), admin reset
     * (public/admin/users.php), and the emailed-link reset
     * (public/reset_password.php) - so a password change always logs other
     * sessions out.
     *
     * The session that performs a *self-service* change re-seeds its own
     * $_SESSION['session_epoch'] to the new value immediately afterwards (see
     * public/password.php) so the person who just changed their password stays
     * signed in on the browser they did it from; only their OTHER sessions are
     * dropped. The admin and emailed-link callers have no such session to
     * preserve (the admin is a different account; the reset link is used while
     * logged out), so they need no follow-up.
     *
     * Trusted-device (skip-MFA) grants are intentionally left alone here - a
     * password change revokes sessions, not devices. The emailed-link reset
     * revokes trusted devices separately, on its own reasoning (that flow
     * proves control of the mailbox, not the device).
     */
    public static function resetPassword(int $userId, string $newPassword): void
    {
        Database::getConnection()
            ->prepare('UPDATE users
                       SET password_hash = :hash,
                           failed_login_attempts = 0,
                           locked_until = NULL,
                           session_epoch = session_epoch + 1
                       WHERE id = :id')
            ->execute(['hash' => password_hash($newPassword, PASSWORD_BCRYPT), 'id' => $userId]);
    }

    public static function deleteUser(int $userId): void
    {
        Database::getConnection()
            ->prepare('DELETE FROM users WHERE id = :id')
            ->execute(['id' => $userId]);
    }

    /**
     * Deletes a tag outright. asset_tags and user_tags rows referencing it
     * are removed automatically by the FK ON DELETE CASCADE already in
     * install_schema.sql - this does NOT delete the assets or users themselves,
     * only their association with this specific tag. A non-admin whose
     * only tag gets deleted this way will see zero data afterwards (the
     * same fail-closed behaviour as never having been assigned a tag at
     * all) until reassigned - the admin UI warns about this with real
     * counts before the confirm dialog fires.
     */
    public static function deleteTag(int $tagId): void
    {
        Database::getConnection()
            ->prepare('DELETE FROM tags WHERE id = :id')
            ->execute(['id' => $tagId]);
    }

    /**
     * The booked CE+ assessment date ('Y-m-d', or null for none) for each of
     * the given tags - see database/migrations/2026-11-add-tag-ce-assessment-date.sql.
     * Its own query rather than a column on listTags()/getTagsByIds(), which
     * every page calls: only the readiness page needs it, so only that page
     * depends on the migration having run.
     *
     * @param int[] $tagIds
     * @return array<int, ?string> tag id => date
     */
    public static function getCeAssessmentDates(array $tagIds): array
    {
        $tagIds = array_values(array_unique(array_map('intval', $tagIds)));
        if ($tagIds === []) {
            return [];
        }
        $stmt = Database::getConnection()->prepare(
            'SELECT id, ce_assessment_date FROM tags WHERE id IN (' . implode(',', array_fill(0, count($tagIds), '?')) . ')'
        );
        $stmt->execute($tagIds);

        $dates = [];
        foreach ($stmt->fetchAll() as $row) {
            $dates[(int)$row['id']] = $row['ce_assessment_date'] !== null ? (string)$row['ce_assessment_date'] : null;
        }
        return $dates;
    }

    /**
     * Sets (or clears, with null) a tag's CE+ assessment date. Persistence
     * only: public/ce_readiness.php checks the caller is an admin and that
     * $date is a real calendar date (CePlusReadiness::parseDate()) first.
     */
    public static function setCeAssessmentDate(int $tagId, ?string $date): void
    {
        Database::getConnection()
            ->prepare('UPDATE tags SET ce_assessment_date = :d WHERE id = :id')
            ->execute(['d' => $date, 'id' => $tagId]);
    }

    /**
     * Sets (or clears, with null) the Cloud Agent activation ID offered for
     * a tag in the Assets page's "Install agent" overlay. Persistence only:
     * public/admin/users.php normalises and validates it first
     * (AgentInstall::normaliseActivationId()).
     */
    /** Sets (or clears, with null) a tag's access end date - see AccessExpiry. */
    public static function setTagExpiresOn(int $tagId, ?string $date): void
    {
        Database::getConnection()
            ->prepare('UPDATE tags SET expires_on = :d WHERE id = :id')
            ->execute(['d' => $date, 'id' => $tagId]);
    }

    /**
     * The tags assigned to an account (its own or its organisation's) that
     * have an access end date - for the client notices in
     * src/views/header.php. Returned whether ended or not; AccessExpiry::notice()
     * decides what to show.
     *
     * @return array<int, array{name: string, expires_on: string}>
     */
    public static function getDatedTags(int $userId): array
    {
        $stmt = Database::getConnection()->prepare('
            SELECT DISTINCT t.name, t.expires_on
            FROM ' . self::EFFECTIVE_TAGS_SQL . ' e
            JOIN tags t ON t.id = e.tag_id
            WHERE e.user_id = :id AND t.expires_on IS NOT NULL
            ORDER BY t.expires_on, t.name
        ');
        $stmt->execute(['id' => $userId]);
        return $stmt->fetchAll();
    }

    public static function setAgentActivationId(int $tagId, ?string $activationId): void
    {
        Database::getConnection()
            ->prepare('UPDATE tags SET agent_activation_id = :a WHERE id = :id')
            ->execute(['a' => $activationId, 'id' => $tagId]);
    }

    /**
     * Creates a tag, either fully known or "pending".
     *
     * $qualysTagId null (or empty) creates a PENDING tag: name known, Qualys
     * numeric ID not yet. This is how a client account can be scoped to a tag
     * before any agent carrying it has reported - the host-detection sync
     * fills in the numeric ID later by promoting this row in place (see
     * resolveSyncedTagId()), at which point the account starts seeing data
     * with no re-assignment needed, because user_tags points at this row's
     * immutable local id. A non-null $qualysTagId is the pre-existing
     * behaviour: a fully-known tag (a numeric tag ID, a tag name, or a Cloud
     * Agent Activation UUID - whatever your Qualys data uses).
     *
     * Rejects a name that collides (case-insensitively, trimmed) with ANY
     * existing tag, pending or live. This is what keeps name-based promotion
     * unambiguous - resolveSyncedTagId() must be able to match an incoming
     * Qualys tag to at most one pending row by name - and it also steers an
     * admin who tries to hand-create a tag that already exists live towards
     * just assigning the existing one (a shadow row could never promote,
     * since the real numeric ID is already taken by the live row). The
     * normalisation here (SQL LOWER(TRIM(...))) is deliberately identical to
     * the one resolveSyncedTagId() uses, so "rejected as a duplicate" and
     * "matched for promotion" can never disagree.
     *
     * @throws \RuntimeException on a duplicate name or duplicate qualys_tag_id
     */
    public static function createTag(?string $qualysTagId, string $name): int
    {
        $pdo = Database::getConnection();

        $qualysTagId = $qualysTagId !== null ? trim($qualysTagId) : '';
        $qualysTagId = $qualysTagId !== '' ? $qualysTagId : null;
        $name = trim($name);

        $dupName = $pdo->prepare(
            'SELECT qualys_tag_id FROM tags WHERE LOWER(TRIM(name)) = LOWER(TRIM(:name)) LIMIT 1'
        );
        $dupName->execute(['name' => $name]);
        $existing = $dupName->fetch();
        if ($existing !== false) {
            throw new \RuntimeException(
                $existing['qualys_tag_id'] === null
                    ? 'A pending tag with that name already exists - it will pick up its Qualys ID '
                      . 'automatically when an agent carrying it first reports.'
                    : 'A tag with that name already exists - assign that one to the account instead.'
            );
        }

        try {
            $stmt = $pdo->prepare('INSERT INTO tags (qualys_tag_id, name) VALUES (:qtag, :name)');
            $stmt->execute(['qtag' => $qualysTagId, 'name' => $name]);
            return (int)$pdo->lastInsertId();
        } catch (\PDOException $e) {
            if ((int)$e->getCode() === 23000 || str_contains($e->getMessage(), 'Duplicate entry')) {
                throw new \RuntimeException('A tag with that Qualys identifier already exists.');
            }
            throw $e;
        }
    }

    /**
     * Resolves the local tags.id to associate a synced host with, given one
     * tag Qualys just reported for it (its numeric ID and its name). This is
     * the single shared resolution point for the live host-detection sync
     * (scripts/sync_host_detections.php), the hourly full reconciliation
     * (scripts/reconcile_asset_inventory.php) and diagnose_tags.php's --full
     * catch-up path - kept in one place specifically so the pending-tag
     * promotion rule below can never drift between them.
     *
     * That "all three" is the point of this method, and it was not true
     * until 2026-07: reconcile_asset_inventory.php carried its own private
     * lookup-by-ID-else-INSERT pair and never consulted pending rows at all.
     * Since that script runs hourly against a FULL, unfiltered pull while
     * the incremental sync only ever sees recently-assessed hosts, it was
     * usually the first job to lay eyes on a newly-tagged host - so it, not
     * the sync, decided what happened to a brand-new tag, and what it did
     * was INSERT a second row. The pending row was then permanently
     * orphaned: step 1 below matched the duplicate from that moment on, so
     * promotion could never fire, and the account assigned to the pending
     * row kept seeing nothing. Observed on the "FaiceTechAgents" tag (a
     * pending row plus a live 101516348 row, same name), resolved by
     * deleting the orphan by hand. This fix is preventive only - it stops
     * new pairs forming and does NOT untangle one that already exists.
     * Check for a leftover with:
     *   SELECT LOWER(TRIM(name)) n, COUNT(*) c FROM tags GROUP BY n HAVING c > 1;
     *
     * Resolution order:
     *   1. Exact match on the numeric Qualys tag ID (qualys_tag_id) - the
     *      normal steady-state path once a tag is known locally. If Qualys
     *      now reports a different name, the row is renamed to match
     *      (2026-11, Mark's call: names follow Qualys). Scoping is by id, so
     *      a rename never changes who sees what - only the label. A name
     *      that is just the id itself is QualysApiClient's fallback for an
     *      empty <NAME>, not a real name, so it never renames anything.
     *   2. Otherwise a PENDING row (qualys_tag_id IS NULL) whose name matches
     *      case-insensitively/trimmed: an admin pre-created this tag by name
     *      before any agent carrying it reported. PROMOTE it in place -
     *      stamp the now-known numeric ID onto that same row - so every
     *      user_tags row already pointing at it (the entire reason to
     *      pre-create) lights up with data without any re-association. The
     *      row's NAME is left as the admin entered it at this point (the
     *      match was case-insensitive, so it can differ only in case or
     *      spacing); step 1 brings it in line with Qualys the next time
     *      the tag is seen.
     *   3. Otherwise INSERT a brand-new fully-known row - the pre-existing
     *      behaviour for a tag nobody pre-created.
     *
     * Concurrency: the live sync holds a lock, but a manual diagnose --full
     * run does not share it, so two processes could in principle both see the
     * same tag as freshly-pending. The promotion UPDATE is guarded with
     * `AND qualys_tag_id IS NULL`; whoever runs second affects zero rows (or
     * trips the UNIQUE key) and falls through to re-read the ID via step 1,
     * rather than double-promoting or dying. The step-3 insert has the same
     * fall-through so a concurrent insert of the same ID is re-read, not
     * fatal. Every path is therefore idempotent, same as the rest of the sync.
     *
     * @param string $qualysTagId the numeric Qualys tag ID as reported by the
     *        API (never empty - the API client drops tags with no TAG_ID
     *        before they ever reach here)
     * @return int local tags.id
     */
    public static function resolveSyncedTagId(\PDO $pdo, string $qualysTagId, string $name): int
    {
        // Prepared once per connection and reused for every tag on every host
        // across the whole sync loop - the same prepare-once discipline the
        // caller used to apply inline before this was centralised here.
        static $stmts = null;
        static $boundPdo = null;
        if ($stmts === null || $boundPdo !== $pdo) {
            $boundPdo = $pdo;
            $stmts = [
                'byId'    => $pdo->prepare('SELECT id FROM tags WHERE qualys_tag_id = :qtag LIMIT 1'),
                'byIdName' => $pdo->prepare('SELECT id, name FROM tags WHERE qualys_tag_id = :qtag LIMIT 1'),
                'rename'  => $pdo->prepare('UPDATE tags SET name = :name WHERE id = :id'),
                'pending' => $pdo->prepare(
                    'SELECT id FROM tags WHERE qualys_tag_id IS NULL '
                    . 'AND LOWER(TRIM(name)) = LOWER(TRIM(:name)) LIMIT 1'
                ),
                'promote' => $pdo->prepare(
                    'UPDATE tags SET qualys_tag_id = :qtag WHERE id = :id AND qualys_tag_id IS NULL'
                ),
                'insert'  => $pdo->prepare('INSERT INTO tags (qualys_tag_id, name) VALUES (:qtag, :name)'),
            ];
        }

        // 1. Known tag - exact match on the numeric Qualys ID, renamed if
        // Qualys's name has changed (byte comparison, so a case-only rename
        // is picked up too).
        $stmts['byIdName']->execute(['qtag' => $qualysTagId]);
        $known = $stmts['byIdName']->fetch(\PDO::FETCH_ASSOC);
        $stmts['byIdName']->closeCursor();
        if ($known !== false) {
            $newName = trim($name);
            if ($newName !== '' && $newName !== $qualysTagId && $newName !== $known['name']) {
                $stmts['rename']->execute(['name' => $newName, 'id' => (int)$known['id']]);
            }
            return (int)$known['id'];
        }

        // 2. Pending tag pre-created by name - promote it in place. The
        // incoming name is trimmed here as well as in SQL because MySQL's
        // TRIM() only strips ASCII spaces, not tabs/newlines - PHP's trim()
        // strips those too, matching what createTag() already applied to the
        // stored side, so an admin-entered name and a Qualys-reported one
        // can't fail to match over invisible whitespace.
        $stmts['pending']->execute(['name' => trim($name)]);
        $pendingId = $stmts['pending']->fetchColumn();
        $stmts['pending']->closeCursor();
        if ($pendingId !== false) {
            try {
                $stmts['promote']->execute(['qtag' => $qualysTagId, 'id' => (int)$pendingId]);
                if ($stmts['promote']->rowCount() > 0) {
                    return (int)$pendingId;
                }
                // Zero rows: a concurrent run promoted it first. Fall through
                // to re-read the now-known ID via step 1.
            } catch (\PDOException $e) {
                // A concurrent run already stamped this numeric ID onto some
                // row (UNIQUE violation) - fall through and re-read it.
                if ((int)$e->getCode() !== 23000 && !str_contains($e->getMessage(), 'Duplicate entry')) {
                    throw $e;
                }
            }
            $stmts['byId']->execute(['qtag' => $qualysTagId]);
            $id = $stmts['byId']->fetchColumn();
            $stmts['byId']->closeCursor();
            if ($id !== false) {
                return (int)$id;
            }
            // Fell through with neither a promotion nor a readable row: drop
            // to a fresh insert as a last resort (extremely unlikely).
        }

        // 3. Brand-new fully-known tag nobody pre-created.
        try {
            $stmts['insert']->execute(['qtag' => $qualysTagId, 'name' => $name]);
            return (int)$pdo->lastInsertId();
        } catch (\PDOException $e) {
            // Concurrent insert of the same ID between our lookup and this
            // insert - re-read it rather than failing the whole host.
            if ((int)$e->getCode() === 23000 || str_contains($e->getMessage(), 'Duplicate entry')) {
                $stmts['byId']->execute(['qtag' => $qualysTagId]);
                $id = $stmts['byId']->fetchColumn();
                $stmts['byId']->closeCursor();
                if ($id !== false) {
                    return (int)$id;
                }
            }
            throw $e;
        }
    }

}
