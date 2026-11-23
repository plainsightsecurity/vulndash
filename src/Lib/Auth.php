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
            'SELECT id, username, password_hash, is_admin, is_active, failed_login_attempts, locked_until, mfa_enabled
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
        $stmt = $pdo->prepare('SELECT tag_id FROM user_tags WHERE user_id = :id');
        $stmt->execute(['id' => $userId]);
        return array_map('intval', array_column($stmt->fetchAll(), 'tag_id'));
    }

    public static function check(): void
    {
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
        $account = UserRepository::getSessionAccount((int)$_SESSION['user_id']);
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

        // Access as it stands now, not as it stood at login: a tag removed,
        // admin rights taken away or the uninstall grant revoked applies from
        // this request on - and one added does too, without a re-login. Every
        // tag-scoped read (Auth::tagIds(), isAdmin(), canUninstall()) reads
        // these, so the fail-closed scope join gets the current set.
        $_SESSION['is_admin']      = $account['is_admin'];
        $_SESSION['tag_ids']       = $account['tag_ids'];
        $_SESSION['can_uninstall'] = $account['can_uninstall'];
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
