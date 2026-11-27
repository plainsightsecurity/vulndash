<?php
declare(strict_types=1);

namespace VulnDash\Lib;

class Auth
{
    private const MAX_FAILED_ATTEMPTS = 5;
    private const LOCKOUT_SECONDS = 900; // 15 minutes

    // A fixed, valid bcrypt hash (of a throwaway string nobody knows) used
    // only to spend the same ~password_verify() time on the "no such
    // account" path as on a real one - see attemptLogin(). Without this,
    // a missing/inactive username returns measurably faster than a wrong
    // password for a real account, turning login into a username oracle
    // (OWASP: user enumeration). The cost factor here should track the one
    // password_hash(PASSWORD_BCRYPT) uses so the two paths stay comparable.
    private const DUMMY_PASSWORD_HASH = '$2y$10$S9AnI6jlHqA7XFCMwxRpn.uRWc/bfdx7Iw.Pl9.1TnLtFoTTzxXam';

    // How long a password-verified-but-not-yet-MFA-verified session may sit
    // in the "pending" state before it's abandoned and the person has to
    // start over from login.php. Keeps a half-authenticated session from
    // lingering indefinitely if someone walks away mid-challenge.
    private const MFA_PENDING_TTL_SECONDS = 300; // 5 minutes

    public const RESULT_SUCCESS = 'success';
    public const RESULT_MFA_REQUIRED = 'mfa_required';
    public const RESULT_FAILED = 'failed';
    // Returned when the client IP has too many recent failed attempts (see
    // LoginThrottleRepository) - distinct from RESULT_FAILED so login.php can
    // show a "too many attempts" message instead of "wrong password", and so
    // we never even reach the credential check for a throttled IP.
    public const RESULT_THROTTLED = 'throttled';
    // Right password, but the account's access end date has passed (see
    // AccessExpiry). Only ever returned after the password is verified, so it
    // tells nobody anything they didn't already know. lastAccessUntil() has
    // the date for the login page's message.
    public const RESULT_EXPIRED = 'expired';

    private static ?string $lastAccessUntil = null;

    /**
     * Verifies username/password and, if both are correct, either finishes
     * login immediately (MFA not enabled for this account, or this browser
     * already holds a valid "trust this device" grant - see
     * TrustedDeviceRepository::isTrusted()) or parks the session in a
     * "password verified, MFA still required" pending state and returns
     * RESULT_MFA_REQUIRED for public/login.php to redirect to
     * public/mfa_verify.php.
     *
     * The session ID is rotated as soon as the password is confirmed
     * (session fixation protection), and rotated again in finalizeLogin()
     * once MFA (if required) also passes - so nothing above the
     * `password_verify()` call ever runs inside the pre-rotation session.
     */
    public static function attemptLogin(string $username, string $password): string
    {
        $pdo = Database::getConnection();

        // Per-IP throttle (password-spraying backstop) sits in front of the
        // credential check: a throttled IP is turned away before we look the
        // account up or verify anything, and without consuming another of the
        // per-account attempts underneath. See LoginThrottleRepository.
        $ip = LoginThrottleRepository::clientIp();
        if (LoginThrottleRepository::isThrottled($ip)) {
            self::auditFailure(null, $username, 'throttled');
            return self::RESULT_THROTTLED;
        }

        // An account may sign in with either its username or its email
        // address. The username is matched as entered; the email is matched
        // lowercased, since emails are stored and treated in lower case. Two
        // distinct placeholders bound to the same input are required because
        // Database.php runs real (non-emulated) prepared statements, where a
        // named placeholder may not appear more than once in one query - same
        // constraint, and same OR-lookup shape, as
        // UserRepository::findByUsernameOrEmail().
        $stmt = $pdo->prepare(
            'SELECT id, username, password_hash, is_admin, failed_login_attempts, locked_until, mfa_enabled,
                    (is_active = 1 AND ' . UserRepository::ORG_ACTIVE_CONDITION . ') AS is_active,
                    expires_on, (SELECT o_ex.expires_on FROM organisations o_ex WHERE o_ex.id = users.organisation_id) AS org_expires_on
             FROM users WHERE username = :login_username OR email = :login_email LIMIT 1'
        );
        $stmt->execute([
            'login_username' => $username,
            'login_email'    => strtolower($username),
        ]);
        $user = $stmt->fetch();

        if (!$user || (int)$user['is_active'] === 0) {
            // Spend the same time here as the real path would in
            // password_verify() below, so "no such account" / "disabled
            // account" can't be told apart from "wrong password" by response
            // time. The result is discarded - this always fails. The IP
            // failure is still recorded so the throttle can't be evaded by
            // aiming at usernames that don't exist.
            password_verify($password, self::DUMMY_PASSWORD_HASH);
            LoginThrottleRepository::recordFailure($ip);
            self::auditFailure($user ?: null, $username, $user ? 'account deactivated' : 'no such account');
            return self::RESULT_FAILED;
        }

        if ($user['locked_until'] !== null && strtotime($user['locked_until']) > time()) {
            LoginThrottleRepository::recordFailure($ip);
            self::auditFailure($user, $username, 'account locked');
            return self::RESULT_FAILED;
        }

        if (!password_verify($password, $user['password_hash'])) {
            self::registerFailedAttempt($pdo, (int)$user['id'], (int)$user['failed_login_attempts']);
            LoginThrottleRepository::recordFailure($ip);
            self::auditFailure($user, $username, 'wrong password');
            return self::RESULT_FAILED;
        }

        // Correct password - clear this IP's failure tally (an ordinary user
        // who mistyped a couple of times shouldn't stay part-way to a block),
        // and reset the *password* lockout counters regardless of what
        // happens next with MFA; a wrong TOTP code afterwards is tracked
        // separately (see MfaService), since it's a different brute-force
        // surface with a much smaller keyspace.
        LoginThrottleRepository::clear($ip);
        $pdo->prepare(
            'UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = :id'
        )->execute(['id' => $user['id']]);

        // Access end date passed (AccessExpiry): checked only now the password
        // is proven, so the login page can say why rather than "incorrect
        // password", without revealing anything to someone guessing.
        $accessUntil = AccessExpiry::effective($user['expires_on'], $user['org_expires_on'], (int)$user['is_admin'] === 1);
        if (AccessExpiry::isExpired($accessUntil)) {
            self::$lastAccessUntil = $accessUntil;
            self::auditFailure($user, $username, 'access expired');
            return self::RESULT_EXPIRED;
        }

        session_regenerate_id(true);

        if ((int)$user['mfa_enabled'] === 1 && !TrustedDeviceRepository::isTrusted((int)$user['id'])) {
            $_SESSION['mfa_pending_user_id'] = (int)$user['id'];
            $_SESSION['mfa_pending_since'] = time();
            return self::RESULT_MFA_REQUIRED;
        }

        self::finalizeLogin($pdo, $user);
        AuditLog::record('auth.login', [
            'details' => ['method' => (int)$user['mfa_enabled'] === 1 ? 'password + trusted device' : 'password'],
        ]);
        return self::RESULT_SUCCESS;
    }

    /**
     * Audit a failed password sign-in. Against a real account the row is
     * attributed to it (so an admin filtering by user sees attacks on that
     * account); otherwise the name that was typed is kept as the target only,
     * trimmed - it's occasionally a mistyped password.
     */
    private static function auditFailure(?array $user, string $typed, string $reason): void
    {
        AuditLog::record('auth.login_failed', $user !== null ? [
            'user_id'  => (int)$user['id'],
            'username' => (string)$user['username'],
            'details'  => ['reason' => $reason],
        ] : [
            'user_id'      => null,
            'username'     => null,
            'target_type'  => 'login',
            'target_label' => mb_substr($typed, 0, 64),
            'details'      => ['reason' => $reason],
        ]);
    }

    /** @return int|null the user ID awaiting MFA verification, or null if no challenge is pending (or it expired). */
    public static function pendingMfaUserId(): ?int
    {
        if (empty($_SESSION['mfa_pending_user_id'])) {
            return null;
        }

        $since = (int)($_SESSION['mfa_pending_since'] ?? 0);
        if (time() - $since > self::MFA_PENDING_TTL_SECONDS) {
            self::cancelMfaChallenge();
            return null;
        }

        return (int)$_SESSION['mfa_pending_user_id'];
    }

    /** Abandons a pending MFA challenge (expired, cancelled, or "not you" link) without logging anyone in. */
    public static function cancelMfaChallenge(): void
    {
        unset($_SESSION['mfa_pending_user_id'], $_SESSION['mfa_pending_since']);
    }

    /**
     * Verifies the submitted TOTP code for whichever login is currently
     * pending (see pendingMfaUserId()), and on success finalizes the
     * login exactly as attemptLogin() would have done directly. Returns
     * one of MfaService::VERIFY_OK / VERIFY_INVALID / VERIFY_LOCKED so
     * public/mfa_verify.php can show the right message.
     */
    public static function completeMfaChallenge(string $code, bool $trustDevice): string
    {
        $userId = self::pendingMfaUserId();
        if ($userId === null) {
            return MfaService::VERIFY_INVALID;
        }

        $result = MfaService::verifyLoginCode($userId, $code);
        if ($result !== MfaService::VERIFY_OK) {
            AuditLog::record('auth.mfa_failed', [
                'user_id'  => $userId,
                'username' => UserRepository::getUser($userId)['username'] ?? null,
                'details'  => ['result' => $result],
            ]);
            return $result;
        }

        $pdo = Database::getConnection();
        $stmt = $pdo->prepare('SELECT id, username, is_admin FROM users WHERE id = :id');
        $stmt->execute(['id' => $userId]);
        $user = $stmt->fetch();
        if (!$user) {
            self::cancelMfaChallenge();
            return MfaService::VERIFY_INVALID;
        }

        self::finalizeLogin($pdo, $user);

        if ($trustDevice) {
            TrustedDeviceRepository::issue($userId);
        }
        AuditLog::record('auth.login', [
            'details' => ['method' => 'password + two-factor code' . ($trustDevice ? ' (device now trusted)' : '')],
        ]);

        return MfaService::VERIFY_OK;
    }

    /**
     * Common tail end of a fully-authenticated login, whether that
     * happened in one step (attemptLogin(), no MFA in the way) or two
     * (attemptLogin() then completeMfaChallenge()). Rotates the session ID
     * again here specifically for the two-step case - the earlier
     * rotation in attemptLogin() only protects the password step; a fresh
     * session ID is bound to the browser only once the account is fully
     * authenticated, MFA included.
     */
    private static function finalizeLogin(\PDO $pdo, array $user): void
    {
        $pdo->prepare('UPDATE users SET last_login_at = NOW() WHERE id = :id')->execute(['id' => $user['id']]);

        session_regenerate_id(true);
        $_SESSION['user_id']  = (int)$user['id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['is_admin'] = (bool)$user['is_admin'];
        $_SESSION['tag_ids']  = self::loadUserTagIds($pdo, (int)$user['id']);
        // Seed the per-session "view as tag" filter from this account's saved
        // default-tag preference, if any (public/preferences.php). Running
        // this on every login also clears any filter left over from a
        // different account on the same browser/session cookie (e.g. a shared
        // machine where the previous person didn't explicitly log out) - a
        // tag filter is a per-login UI preference, never something that should
        // survive across accounts. Helpers::resolveViewTag() independently
        // re-validates this value against what the account may actually see on
        // every request, so a since-deleted or no-longer-assigned default just
        // falls back to "All tags" rather than applying.
        //
        // Loaded fresh here rather than read off $user because the two login
        // paths that reach this method pass different column sets (the direct
        // path carries the full row; the post-MFA path only id/username/is_admin).
        $defaultTagId = UserRepository::getDefaultTagId((int)$user['id']);
        if ($defaultTagId !== null) {
            $_SESSION['view_tag_id'] = $defaultTagId;
        } else {
            unset($_SESSION['view_tag_id']);
        }

        // Snapshot the account's current session-invalidation epoch into this
        // session. check() re-reads the column on every request and signs the
        // session out if the stored value no longer matches - which is how a
        // password change elsewhere (UserRepository::resetPassword() bumps the
        // epoch) logs every OTHER session out while leaving the one that made
        // the change alone (it re-seeds its own copy - see public/password.php).
        // Read fresh here for the same reason as the default tag above: the two
        // login paths carry different column sets.
        $_SESSION['session_epoch'] = UserRepository::getSessionEpoch((int)$user['id']) ?? 0;

        // Whether this account may request agent uninstalls from the dashboard.
        // Loaded fresh (not read off $user) for the same reason as the two
        // values above: the post-MFA login path only carries id/username/
        // is_admin. This seeds the UI (show/hide the uninstall controls); the
        // actual enqueue in public/assets.php re-checks the flag against the DB
        // at action time so an admin revoking it takes effect immediately,
        // without waiting for the client's next login.
        $_SESSION['can_uninstall'] = UserRepository::getCanUninstall((int)$user['id']);

        unset($_SESSION['mfa_pending_user_id'], $_SESSION['mfa_pending_since']);

        // Starts the idle and absolute session timeouts (SessionTimeout).
        SessionTimeout::markLogin();
    }

    private static function registerFailedAttempt(\PDO $pdo, int $userId, int $currentAttempts): void
    {
        $attempts = $currentAttempts + 1;
        $lockedUntil = $attempts >= self::MAX_FAILED_ATTEMPTS
            ? date('Y-m-d H:i:s', time() + self::LOCKOUT_SECONDS)
            : null;

        $pdo->prepare('UPDATE users SET failed_login_attempts = :attempts, locked_until = :locked WHERE id = :id')
            ->execute(['attempts' => $attempts, 'locked' => $lockedUntil, 'id' => $userId]);
        if ($lockedUntil !== null) {
            AuditLog::record('auth.account_locked', [
                'user_id'  => $userId,
                'username' => UserRepository::getUser($userId)['username'] ?? null,
                'details'  => ['locked_until' => $lockedUntil, 'failed_attempts' => $attempts],
            ]);
        }
    }

    /** @return int[] */
    private static function loadUserTagIds(\PDO $pdo, int $userId): array
    {
        // Own extras plus the organisation's tags (UserRepository::EFFECTIVE_TAGS_SQL).
        return UserRepository::getEffectiveTagIds($userId);
    }

    public static function check(): void
    {
        // Idle (8h) and absolute (12h) timeouts - empties the session if
        // either has run out, so the check below sends it to the login page,
        // which explains why. See SessionTimeout.
        SessionTimeout::enforce();

        if (empty($_SESSION['user_id'])) {
            header('Location: /login');
            exit;
        }

        // Server-side session validity: re-read the account's current
        // session-invalidation epoch and compare it to the value this session
        // was issued (see Auth::finalizeLogin()). A password change bumps the
        // stored epoch (UserRepository::resetPassword()), so any session still
        // carrying the old value - i.e. every session other than the one that
        // made the change, which re-seeds its own - is signed out here on its
        // next request. A deleted account (null epoch) is likewise invalidated.
        //
        // This is one extra indexed lookup per authenticated request, which is
        // the price of being able to revoke sessions at all with PHP's native
        // session storage.
        //
        // The same lookup (2026-11) also returns the account's CURRENT access,
        // which replaces the copy taken at login below - see
        // UserRepository::getSessionAccount() for the gap this closes.
        $impersonator = self::impersonator();
        if ($impersonator !== null) {
            // "View as": the person at the keyboard is the admin, so it's the
            // admin's account - not the one being viewed - that decides whether
            // this session stays valid. Losing admin rights, being deactivated
            // or a password change on the admin account ends the whole session,
            // exactly as it would have without impersonation.
            $admin = UserRepository::getSessionAccount($impersonator['user_id']);
            if ($admin === null || !$admin['is_active'] || !$admin['is_admin']
                || $admin['session_epoch'] !== $impersonator['session_epoch']) {
                self::logout();
                header('Location: /login');
                exit;
            }

            // The viewed account is deliberately NOT held to the active/epoch
            // checks below: viewing a deactivated account (or one in a
            // suspended organisation) is allowed for troubleshooting, and the
            // client changing their own password shouldn't throw the admin out.
            // It must still exist and still be a non-admin - an admin can never
            // be viewed as, so promotion mid-session ends the view.
            $account = UserRepository::getSessionAccount((int)$_SESSION['user_id']);
            if ($account === null || $account['is_admin']) {
                self::stopImpersonation($account === null ? 'account deleted' : 'account made admin');
                Helpers::setFlash('Stopped viewing as that account - it was deleted or made an admin.', 'error');
                header('Location: /admin/users');
                exit;
            }
        } else {
            $account = self::checkOwnAccount();
        }

        // Access as it stands now, not as it stood at login: a tag removed,
        // admin rights taken away or the uninstall grant revoked applies from
        // this request on - and one added does too, without a re-login. Every
        // tag-scoped read (Auth::tagIds(), isAdmin(), canUninstall()) reads
        // these, so the fail-closed scope join gets the current set. While
        // viewing as someone these are THEIR access, which is the point.
        $_SESSION['is_admin']      = $account['is_admin'];
        $_SESSION['tag_ids']       = $account['tag_ids'];
        $_SESSION['can_uninstall'] = $account['can_uninstall'];
        $_SESSION['is_org_admin']  = $account['is_org_admin'];
        $_SESSION['organisation_id'] = $account['organisation_id'];
        $_SESSION['access_until']  = $account['access_until'];
    }

    /**
     * The ordinary (not "view as") half of check(): the signed-in account must
     * still exist, be active and carry the session epoch this session was
     * issued. Signs the session out and exits otherwise.
     *
     * @return array the account as UserRepository::getSessionAccount() returns it
     */
    private static function checkOwnAccount(): array
    {
        $account = UserRepository::getSessionAccount((int)$_SESSION['user_id']);
        if ($account !== null && $account['expired']) {
            // Access end date has passed (AccessExpiry) - same as deactivated,
            // but the login page says why. Emptied rather than destroyed (like
            // SessionTimeout::enforce()) so the reason survives to that page.
            AuditLog::record('auth.access_expired', ['details' => ['access_until' => $account['access_until']]]);
            $_SESSION = [];
            if (session_status() === PHP_SESSION_ACTIVE) {
                session_regenerate_id(true);
            }
            $_SESSION['signed_out_reason'] = SessionTimeout::REASON_ACCESS_EXPIRED;
            $_SESSION['signed_out_access_until'] = $account['access_until'];
            header('Location: /login');
            exit;
        }
        if ($account === null || !$account['is_active']) {
            // Account deleted or deactivated - drop the session. Deactivating
            // used to leave existing sessions working until they ended.
            self::logout();
            header('Location: /login');
            exit;
        }
        $currentEpoch = $account['session_epoch'];

        if (!isset($_SESSION['session_epoch'])) {
            // A session established before this column existed (i.e. one that
            // was already logged in when this change was deployed). It's a
            // legitimately authenticated session and predates any revocation
            // event, so adopt the current epoch rather than force a re-login.
            $_SESSION['session_epoch'] = $currentEpoch;
        } elseif ((int)$_SESSION['session_epoch'] !== $currentEpoch) {
            // Password changed (or sessions otherwise invalidated) elsewhere
            // since this session was issued. Trusted-device grants are left
            // untouched - a password change revokes sessions, not devices - so
            // signing back in on a known browser still skips the MFA prompt.
            self::logout();
            header('Location: /login');
            exit;
        }

        return $account;
    }

    /**
     * Starts "view as" for an admin: from the next request this session sees
     * exactly what $targetId sees - same tags, same per-account hides, same
     * preferences, organisation-admin pages if they have them - and can act as
     * them. The admin's own identity is parked in $_SESSION['impersonator'] so
     * check() keeps validating the admin's account, AuditLog keeps recording
     * the admin as the actor, and stopImpersonation() can put it all back.
     *
     * Caller must already have confirmed the session is a (non-impersonating)
     * admin - see public/admin/impersonate.php.
     *
     * @throws \InvalidArgumentException when the target can't be viewed as
     */
    public static function startImpersonation(int $targetId): void
    {
        if (self::isImpersonating()) {
            throw new \InvalidArgumentException('Already viewing as another account - return to admin first.');
        }
        $target = UserRepository::getUser($targetId);
        if (!$target) {
            throw new \InvalidArgumentException('That account no longer exists.');
        }
        // Admins see everything already, and viewing as one would hand this
        // session someone else's admin identity - never useful, so never allowed.
        if (!empty($target['is_admin'])) {
            throw new \InvalidArgumentException('Admin accounts can\'t be viewed as.');
        }
        $account = UserRepository::getSessionAccount($targetId);
        if ($account === null) {
            throw new \InvalidArgumentException('That account no longer exists.');
        }

        $adminId = self::userId();
        AuditLog::record('admin.impersonation_started', [
            'target_type'  => 'user',
            'target_id'    => $targetId,
            'target_label' => (string)$target['username'],
        ]);

        $_SESSION['impersonator'] = [
            'user_id'       => $adminId,
            'username'      => self::username(),
            'session_epoch' => isset($_SESSION['session_epoch'])
                ? (int)$_SESSION['session_epoch']
                : (UserRepository::getSessionEpoch($adminId) ?? 0),
            // The admin's own UI state, restored on the way back so returning
            // to admin lands where they left off.
            'view_tag_id'   => $_SESSION['view_tag_id'] ?? null,
            'show_hidden'   => $_SESSION['show_hidden'] ?? null,
            'started_at'    => time(),
        ];

        // Identity changes, so the session ID does too (same reasoning as
        // finalizeLogin()). The CSRF token and timeouts carry over: it's still
        // the admin's sign-in. Guarded only for the CLI test harness, which
        // has no real session.
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_regenerate_id(true);
        }
        $_SESSION['user_id']         = $targetId;
        $_SESSION['username']        = (string)$target['username'];
        $_SESSION['is_admin']        = false;
        $_SESSION['tag_ids']         = $account['tag_ids'];
        $_SESSION['can_uninstall']   = $account['can_uninstall'];
        $_SESSION['is_org_admin']    = $account['is_org_admin'];
        $_SESSION['organisation_id'] = $account['organisation_id'];
        $_SESSION['access_until']    = $account['access_until'];
        // Start from the view the client would get at sign-in, not the admin's.
        $defaultTagId = UserRepository::getDefaultTagId($targetId);
        if ($defaultTagId !== null) {
            $_SESSION['view_tag_id'] = $defaultTagId;
        } else {
            unset($_SESSION['view_tag_id']);
        }
        unset($_SESSION['show_hidden']);
    }

    /**
     * Ends "view as" and puts the admin's own identity back. The next check()
     * reloads the admin's current access. No-op if not impersonating.
     */
    public static function stopImpersonation(?string $reason = null): void
    {
        $imp = self::impersonator();
        if ($imp === null) {
            return;
        }
        $viewedId   = self::userId();
        $viewedName = self::username();

        if (session_status() === PHP_SESSION_ACTIVE) {
            session_regenerate_id(true);
        }
        $_SESSION['user_id']       = $imp['user_id'];
        $_SESSION['username']      = $imp['username'];
        $_SESSION['session_epoch'] = $imp['session_epoch'];
        // Restored optimistically; check() re-reads the real values on the
        // next request (and signs out if the admin is no longer an admin).
        $_SESSION['is_admin']      = true;
        $_SESSION['tag_ids']       = [];
        unset($_SESSION['is_org_admin'], $_SESSION['organisation_id']);
        foreach (['view_tag_id', 'show_hidden'] as $k) {
            if ($imp[$k] !== null) {
                $_SESSION[$k] = $imp[$k];
            } else {
                unset($_SESSION[$k]);
            }
        }
        unset($_SESSION['impersonator']);

        // Recorded after the swap back, so the admin is the actor without the
        // "viewing as" annotation AuditLog adds during impersonation.
        $details = ['duration_seconds' => max(0, time() - $imp['started_at'])];
        if ($reason !== null) {
            $details['reason'] = $reason;
        }
        AuditLog::record('admin.impersonation_ended', [
            'target_type'  => 'user',
            'target_id'    => $viewedId,
            'target_label' => $viewedName,
            'details'      => $details,
        ]);
    }

    public static function isImpersonating(): bool
    {
        return self::impersonator() !== null;
    }

    /**
     * The admin behind a "view as" session, or null when the session is
     * nobody's but its own.
     *
     * @return array{user_id: int, username: string, session_epoch: int, view_tag_id: ?int, show_hidden: ?bool, started_at: int}|null
     */
    public static function impersonator(): ?array
    {
        $imp = $_SESSION['impersonator'] ?? null;
        if (!is_array($imp) || empty($imp['user_id'])) {
            return null;
        }
        return [
            'user_id'       => (int)$imp['user_id'],
            'username'      => (string)($imp['username'] ?? ''),
            'session_epoch' => (int)($imp['session_epoch'] ?? 0),
            'view_tag_id'   => isset($imp['view_tag_id']) ? (int)$imp['view_tag_id'] : null,
            'show_hidden'   => isset($imp['show_hidden']) ? (bool)$imp['show_hidden'] : null,
            'started_at'    => (int)($imp['started_at'] ?? time()),
        ];
    }

    /**
     * For /org/* pages: signed in, a member of an active organisation and its
     * organisation admin, as of THIS request (check() re-reads all of that).
     * Plainsight admins aren't in an organisation and use /admin pages.
     *
     * @return int the organisation id every action on the page is confined to
     */
    public static function requireOrgAdmin(): int
    {
        self::check();
        $orgId = isset($_SESSION['organisation_id']) ? (int)$_SESSION['organisation_id'] : 0;
        if (empty($_SESSION['is_org_admin']) || $orgId <= 0) {
            self::forbidden();
        }
        return $orgId;
    }

    private static function forbidden(): never
    {
        http_response_code(403);
        header('Content-Type: text/html; charset=UTF-8');
        echo '<!DOCTYPE html><html><head><title>403 Forbidden</title></head>'
           . '<body style="font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1.5rem;">'
           . '<h1>403 Forbidden</h1><p>You do not have permission to view this page.</p>'
           . '<p><a href="/dashboard">Return to dashboard</a></p></body></html>';
        exit;
    }

    /** Blocks non-admins from admin-only pages with a plain 403, rather than redirecting. */
    public static function requireAdmin(): void
    {
        self::check();
        if (!self::isAdmin()) {
            http_response_code(403);
            header('Content-Type: text/html; charset=UTF-8');
            echo '<!DOCTYPE html><html><head><title>403 Forbidden</title></head>'
               . '<body style="font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1.5rem;">'
               . '<h1>403 Forbidden</h1><p>You do not have permission to view this page.</p>'
               . '<p><a href="/dashboard">Return to dashboard</a></p></body></html>';
            exit;
        }
    }

    public static function logout(): void
    {
        if (!empty($_SESSION['user_id'])) {
            AuditLog::record('auth.logout');
        }
        $_SESSION = [];
        if (ini_get('session.use_cookies')) {
            $params = session_get_cookie_params();
            setcookie(
                session_name(),
                '',
                time() - 42000,
                $params['path'],
                $params['domain'],
                $params['secure'],
                $params['httponly']
            );
        }
        session_destroy();
    }

    /** The signed-in (or viewed-as) account's access end date, if it has one - see AccessExpiry. */
    public static function accessUntil(): ?string
    {
        $d = $_SESSION['access_until'] ?? null;
        return is_string($d) && $d !== '' ? $d : null;
    }

    /** The access end date behind the last RESULT_EXPIRED from attemptLogin(). */
    public static function lastAccessUntil(): ?string
    {
        return self::$lastAccessUntil;
    }

    public static function isAdmin(): bool
    {
        return !empty($_SESSION['is_admin']);
    }

    /**
     * Session-level view of whether this account may request agent uninstalls,
     * used to show/hide the controls. Admins are always capable; client
     * accounts need the explicit grant (users.can_uninstall_agents). The
     * authoritative check before actually queuing an uninstall is a fresh DB
     * read in public/assets.php - see the note in finalizeLogin().
     */
    public static function canUninstall(): bool
    {
        return !empty($_SESSION['is_admin']) || !empty($_SESSION['can_uninstall']);
    }

    /** @return int[] */
    public static function tagIds(): array
    {
        return $_SESSION['tag_ids'] ?? [];
    }

    public static function username(): string
    {
        return $_SESSION['username'] ?? '';
    }

    public static function userId(): int
    {
        return (int)($_SESSION['user_id'] ?? 0);
    }
}
