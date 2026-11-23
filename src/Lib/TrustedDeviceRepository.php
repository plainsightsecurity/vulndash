<?php
declare(strict_types=1);

namespace VulnDash\Lib;

/**
 * "Trust this device" grants - created at the login-time MFA challenge
 * (see public/mfa_verify.php) when the person checks that box, so a
 * subsequent login from the same browser skips the TOTP prompt for a
 * while. Password is always still required regardless of trust status;
 * this only ever skips the second factor.
 *
 * The cookie carries `selector.validator`. `selector` is an indexed
 * lookup key with nothing secret about it on its own; `validator` is
 * never stored - only sha256(validator) is, in token_hash - so a stolen
 * database dump alone can't be replayed as a valid trusted-device cookie,
 * the same reasoning as password_hash for passwords (just without
 * bcrypt's deliberate slowness, which isn't needed for a random 256-bit
 * token that isn't guessable by brute force the way a human password is).
 *
 * Revocation is soft (revoked_at/revoked_by) rather than a DELETE, so both
 * the admin UI (src/Lib/UserRepository.php's callers) and this account's
 * own MFA page (public/mfa.php) leave an audit trail of who revoked what
 * and when, rather than the row just vanishing.
 */
final class TrustedDeviceRepository
{
    private const COOKIE_NAME = 'vulndash_trusted_device';
    private const TRUST_DAYS = 30;

    /**
     * Checks the trusted-device cookie (if any) against $userId. Does NOT
     * check the password - callers must already have verified that
     * separately. On a valid match, also bumps last_used_at so the
     * trusted-devices list reflects genuinely recent activity.
     */
    public static function isTrusted(int $userId): bool
    {
        $token = $_COOKIE[self::COOKIE_NAME] ?? null;
        if (!is_string($token) || !str_contains($token, '.')) {
            return false;
        }

        [$selector, $validator] = explode('.', $token, 2);
        if ($selector === '' || $validator === '') {
            return false;
        }

        $pdo = Database::getConnection();
        $stmt = $pdo->prepare(
            'SELECT id, user_id, token_hash FROM user_trusted_devices
             WHERE selector = :selector AND revoked_at IS NULL AND expires_at > NOW() LIMIT 1'
        );
        $stmt->execute(['selector' => $selector]);
        $device = $stmt->fetch();

        if (!$device || (int)$device['user_id'] !== $userId) {
            return false;
        }
        if (!hash_equals($device['token_hash'], hash('sha256', $validator))) {
            return false;
        }

        $pdo->prepare('UPDATE user_trusted_devices SET last_used_at = NOW() WHERE id = :id')
            ->execute(['id' => $device['id']]);

        return true;
    }

    /** Creates a new trust grant for $userId and sets the cookie on the current response. */
    public static function issue(int $userId): void
    {
        $selector = bin2hex(random_bytes(12));  // 24 hex chars, indexed lookup key
        $validator = bin2hex(random_bytes(32)); // 64 hex chars, never stored - only its hash is
        $expiresAtTs = time() + self::TRUST_DAYS * 86400;

        Database::getConnection()->prepare(
            'INSERT INTO user_trusted_devices (user_id, selector, token_hash, device_label, ip_address, expires_at)
             VALUES (:user_id, :selector, :hash, :label, :ip, :expires)'
        )->execute([
            'user_id'  => $userId,
            'selector' => $selector,
            'hash'     => hash('sha256', $validator),
            'label'    => self::describeUserAgent((string)($_SERVER['HTTP_USER_AGENT'] ?? '')),
            'ip'       => $_SERVER['REMOTE_ADDR'] ?? null,
            'expires'  => date('Y-m-d H:i:s', $expiresAtTs),
        ]);

        setcookie(self::COOKIE_NAME, $selector . '.' . $validator, [
            'expires'  => $expiresAtTs,
            'path'     => '/',
            'domain'   => '',
            // Same HTTPS-only assumption as the session cookie in
            // bootstrap.php - only set this to false if temporarily
            // testing over plain HTTP locally.
            'secure'   => true,
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
    }

    /** Expires the trusted-device cookie on the current response, without touching any database rows. */
    public static function clearCookie(): void
    {
        setcookie(self::COOKIE_NAME, '', [
            'expires'  => time() - 42000,
            'path'     => '/',
            'domain'   => '',
            'secure'   => true,
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
    }

    /**
     * Active (non-revoked, non-expired) trusted devices for one account -
     * used by both the self-service list on public/mfa.php and, indirectly
     * via listForUsers() below, the admin Manage Users page.
     *
     * @return array<int, array<string, mixed>>
     */
    public static function listForUser(int $userId): array
    {
        $stmt = Database::getConnection()->prepare(
            'SELECT id, device_label, ip_address, created_at, last_used_at, expires_at
             FROM user_trusted_devices
             WHERE user_id = :id AND revoked_at IS NULL AND expires_at > NOW()
             ORDER BY COALESCE(last_used_at, created_at) DESC'
        );
        $stmt->execute(['id' => $userId]);
        return $stmt->fetchAll();
    }

    /**
     * Same as listForUser(), batched across several accounts and grouped
     * by user_id - lets the admin Manage Users page show every account's
     * trusted devices with one extra query instead of one per row.
     *
     * @param int[] $userIds
     * @return array<int, array<int, array<string, mixed>>> keyed by user_id
     */
    public static function listForUsers(array $userIds): array
    {
        $userIds = array_values(array_unique(array_map('intval', $userIds)));
        if (empty($userIds)) {
            return [];
        }

        $placeholders = implode(',', array_fill(0, count($userIds), '?'));
        $stmt = Database::getConnection()->prepare(
            "SELECT id, user_id, device_label, ip_address, created_at, last_used_at, expires_at
             FROM user_trusted_devices
             WHERE user_id IN ($placeholders) AND revoked_at IS NULL AND expires_at > NOW()
             ORDER BY user_id, COALESCE(last_used_at, created_at) DESC"
        );
        $stmt->execute($userIds);

        $grouped = [];
        foreach ($stmt->fetchAll() as $row) {
            $grouped[(int)$row['user_id']][] = $row;
        }
        return $grouped;
    }

    /**
     * Revokes one device, scoped to $ownerUserId so one account can never
     * revoke another's device just by guessing/submitting an ID - true
     * whether the caller is the account owner revoking their own device
     * (public/mfa.php) or an admin revoking a device on someone else's
     * account (public/admin/users.php passes that user's ID here, not the
     * admin's own).
     *
     * @return bool true if a matching, not-already-revoked row was found
     */
    public static function revoke(int $deviceId, int $ownerUserId, int $revokedByUserId): bool
    {
        $stmt = Database::getConnection()->prepare(
            'UPDATE user_trusted_devices SET revoked_at = NOW(), revoked_by = :by
             WHERE id = :id AND user_id = :owner AND revoked_at IS NULL'
        );
        $stmt->execute(['by' => $revokedByUserId, 'id' => $deviceId, 'owner' => $ownerUserId]);
        return $stmt->rowCount() > 0;
    }

    public static function revokeAllForUser(int $userId, ?int $revokedByUserId = null): void
    {
        Database::getConnection()->prepare(
            'UPDATE user_trusted_devices SET revoked_at = NOW(), revoked_by = :by
             WHERE user_id = :id AND revoked_at IS NULL'
        )->execute(['by' => $revokedByUserId, 'id' => $userId]);
    }

    public static function countForUser(int $userId): int
    {
        $stmt = Database::getConnection()->prepare(
            'SELECT COUNT(*) AS c FROM user_trusted_devices WHERE user_id = :id AND revoked_at IS NULL AND expires_at > NOW()'
        );
        $stmt->execute(['id' => $userId]);
        return (int)($stmt->fetch()['c'] ?? 0);
    }

    /**
     * Best-effort, coarse label for display only ("Chrome on Windows") -
     * never used for any security decision (the selector/validator pair
     * is what actually authorizes anything), just a hint so a person can
     * tell devices apart in a trusted-devices list.
     */
    private static function describeUserAgent(string $ua): string
    {
        $browser = 'Unknown browser';
        if (stripos($ua, 'Edg/') !== false) {
            $browser = 'Edge';
        } elseif (stripos($ua, 'Chrome/') !== false && stripos($ua, 'Chromium') === false) {
            $browser = 'Chrome';
        } elseif (stripos($ua, 'Firefox/') !== false) {
            $browser = 'Firefox';
        } elseif (stripos($ua, 'Safari/') !== false && stripos($ua, 'Chrome') === false) {
            $browser = 'Safari';
        }

        $os = 'Unknown OS';
        if (stripos($ua, 'Windows') !== false) {
            $os = 'Windows';
        } elseif (stripos($ua, 'Mac OS X') !== false) {
            $os = 'macOS';
        } elseif (stripos($ua, 'Android') !== false) {
            $os = 'Android';
        } elseif (stripos($ua, 'iPhone') !== false || stripos($ua, 'iPad') !== false) {
            $os = 'iOS';
        } elseif (stripos($ua, 'Linux') !== false) {
            $os = 'Linux';
        }

        return $browser . ' on ' . $os;
    }
}
