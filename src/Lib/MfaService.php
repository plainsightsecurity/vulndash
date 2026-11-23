<?php
declare(strict_types=1);

namespace VulnDash\Lib;

/**
 * Business logic for TOTP MFA: secret encryption at rest, the
 * enroll -> confirm enrollment flow, disabling, and login-time code
 * verification (with its own rate limit and replay protection, separate
 * from Totp.php's stateless RFC math - see that class's docblock).
 *
 * The secret is encrypted (AES-256-GCM) using a key from
 * config('security.mfa_encryption_key') rather than stored in plaintext -
 * unlike a password, a TOTP secret has to be reversible to be useful, so
 * it can't be hashed the way password_hash is; encrypting it at rest means
 * a database-only compromise (a leaked backup, a SQL injection read, etc)
 * doesn't hand over live second-factor codes along with it, only the
 * password hashes it already would have. This fails closed if the key
 * isn't configured - see encryptionKey() - rather than silently falling
 * back to storing secrets in plaintext.
 */
final class MfaService
{
    private const CIPHER = 'aes-256-gcm';
    private const GCM_IV_BYTES = 12;
    private const GCM_TAG_BYTES = 16;

    // A 6-digit code has only 1,000,000 possible values - far fewer than a
    // password - so this needs its own (tighter, separately-tracked)
    // lockout independent of the password lockout in Auth.php.
    private const MAX_FAILED_ATTEMPTS = 5;
    private const LOCKOUT_SECONDS = 900; // 15 minutes

    // +/- 1 step (30s) either side of "now" - tolerates ordinary clock
    // drift between the server and the person's phone without opening a
    // wide replay window.
    private const VERIFY_WINDOW = 1;

    public const VERIFY_OK = 'ok';
    public const VERIFY_INVALID = 'invalid';
    public const VERIFY_LOCKED = 'locked';

    /**
     * Generates a new secret and stores it *pending* (mfa_enabled stays 0,
     * mfa_confirmed_at stays NULL) until confirm() proves the person
     * actually has it loaded in an authenticator app. Safe to call again
     * before confirming - e.g. the person wants to switch apps or start
     * over - it simply overwrites whatever pending secret existed.
     *
     * @return array{secret: string, uri: string} the plaintext base32
     *         secret (for display, and for building the QR/otpauth URI)
     *         and the provisioning URI itself. Never returned again after
     *         this call - only the encrypted form is persisted.
     */
    public static function beginEnrollment(int $userId, string $username, string $issuer): array
    {
        $secret = Totp::generateSecret();
        $encrypted = self::encryptSecret($secret);

        Database::getConnection()->prepare(
            'UPDATE users
             SET mfa_secret = :secret, mfa_confirmed_at = NULL, mfa_last_used_counter = NULL,
                 mfa_failed_attempts = 0, mfa_locked_until = NULL
             WHERE id = :id'
        )->execute(['secret' => $encrypted, 'id' => $userId]);

        return [
            'secret' => $secret,
            'uri'    => Totp::provisioningUri($secret, $username, $issuer),
        ];
    }

    /**
     * Re-derives the provisioning URI for whatever enrollment is currently
     * pending, so refreshing the setup page shows the same QR code instead
     * of silently generating a new secret (which would invalidate a code
     * the person already scanned).
     *
     * @return array{secret: string, uri: string}|null null if no pending
     *         secret exists (nothing started, or already confirmed/disabled).
     */
    public static function pendingEnrollment(int $userId, string $username, string $issuer): ?array
    {
        $stmt = Database::getConnection()->prepare(
            'SELECT mfa_secret FROM users WHERE id = :id AND mfa_enabled = 0 AND mfa_secret IS NOT NULL'
        );
        $stmt->execute(['id' => $userId]);
        $row = $stmt->fetch();
        if (!$row) {
            return null;
        }

        $secret = self::decryptSecret($row['mfa_secret']);
        return [
            'secret' => $secret,
            'uri'    => Totp::provisioningUri($secret, $username, $issuer),
        ];
    }

    /** Discards a pending (unconfirmed) enrollment without affecting an already-enabled MFA setup. */
    public static function cancelEnrollment(int $userId): void
    {
        Database::getConnection()->prepare(
            'UPDATE users SET mfa_secret = NULL, mfa_confirmed_at = NULL WHERE id = :id AND mfa_enabled = 0'
        )->execute(['id' => $userId]);
    }

    /**
     * Proves the person actually has the pending secret loaded (a valid
     * code from it), then flips mfa_enabled on. This is the only path that
     * turns MFA on - beginEnrollment() alone never does.
     */
    public static function confirmEnrollment(int $userId, string $code): bool
    {
        $pdo = Database::getConnection();
        $stmt = $pdo->prepare('SELECT mfa_secret FROM users WHERE id = :id AND mfa_enabled = 0');
        $stmt->execute(['id' => $userId]);
        $row = $stmt->fetch();
        if (!$row || !$row['mfa_secret']) {
            return false;
        }

        $secret = self::decryptSecret($row['mfa_secret']);
        $counter = Totp::verify($secret, $code, self::VERIFY_WINDOW);
        if ($counter === null) {
            return false;
        }

        $pdo->prepare(
            'UPDATE users
             SET mfa_enabled = 1, mfa_confirmed_at = NOW(), mfa_last_used_counter = :counter,
                 mfa_failed_attempts = 0, mfa_locked_until = NULL
             WHERE id = :id'
        )->execute(['counter' => $counter, 'id' => $userId]);

        return true;
    }

    /**
     * Fully disables MFA and wipes the secret - used both for self-service
     * "turn off two-factor" (after a password re-check - see
     * public/mfa.php) and for an admin's "reset MFA" recovery action for a
     * user who lost their device (see public/admin/users.php). Also
     * revokes every trusted device for the account: with MFA gone there's
     * no second factor left for a "skip the second factor" grant to mean
     * anything, and leaving them live would let a previously-trusted
     * browser silently carry that trust into whatever MFA setup (if any)
     * the person creates next.
     */
    public static function disable(int $userId): void
    {
        Database::getConnection()->prepare(
            'UPDATE users
             SET mfa_enabled = 0, mfa_secret = NULL, mfa_confirmed_at = NULL,
                 mfa_failed_attempts = 0, mfa_locked_until = NULL, mfa_last_used_counter = NULL
             WHERE id = :id'
        )->execute(['id' => $userId]);

        TrustedDeviceRepository::revokeAllForUser($userId);
    }

    /**
     * Verifies a submitted code during the login MFA challenge (see
     * public/mfa_verify.php). Handles the MFA-specific lockout and updates
     * mfa_last_used_counter for replay protection on success.
     */
    public static function verifyLoginCode(int $userId, string $code): string
    {
        $pdo = Database::getConnection();
        $stmt = $pdo->prepare(
            'SELECT mfa_secret, mfa_failed_attempts, mfa_locked_until, mfa_last_used_counter
             FROM users WHERE id = :id AND mfa_enabled = 1'
        );
        $stmt->execute(['id' => $userId]);
        $row = $stmt->fetch();
        if (!$row || !$row['mfa_secret']) {
            return self::VERIFY_INVALID;
        }

        if ($row['mfa_locked_until'] !== null && strtotime($row['mfa_locked_until']) > time()) {
            return self::VERIFY_LOCKED;
        }

        $secret = self::decryptSecret($row['mfa_secret']);
        $lastCounter = $row['mfa_last_used_counter'] !== null ? (int)$row['mfa_last_used_counter'] : null;
        $counter = Totp::verify($secret, $code, self::VERIFY_WINDOW, null, $lastCounter);

        if ($counter === null) {
            $attempts = (int)$row['mfa_failed_attempts'] + 1;
            $lockedUntil = $attempts >= self::MAX_FAILED_ATTEMPTS
                ? date('Y-m-d H:i:s', time() + self::LOCKOUT_SECONDS)
                : null;
            $pdo->prepare('UPDATE users SET mfa_failed_attempts = :a, mfa_locked_until = :l WHERE id = :id')
                ->execute(['a' => $attempts, 'l' => $lockedUntil, 'id' => $userId]);
            return self::VERIFY_INVALID;
        }

        $pdo->prepare(
            'UPDATE users SET mfa_failed_attempts = 0, mfa_locked_until = NULL, mfa_last_used_counter = :counter WHERE id = :id'
        )->execute(['counter' => $counter, 'id' => $userId]);

        return self::VERIFY_OK;
    }

    public static function encryptSecret(string $plainSecret): string
    {
        $key = self::encryptionKey();
        $iv = random_bytes(self::GCM_IV_BYTES);
        $tag = '';
        $cipherText = openssl_encrypt($plainSecret, self::CIPHER, $key, OPENSSL_RAW_DATA, $iv, $tag);
        if ($cipherText === false) {
            throw new \RuntimeException('Failed to encrypt MFA secret.');
        }

        return base64_encode($iv . $tag . $cipherText);
    }

    public static function decryptSecret(string $encoded): string
    {
        $key = self::encryptionKey();
        $raw = base64_decode($encoded, true);
        $minLength = self::GCM_IV_BYTES + self::GCM_TAG_BYTES;
        if ($raw === false || strlen($raw) < $minLength) {
            throw new \RuntimeException('Stored MFA secret is corrupt.');
        }

        $iv = substr($raw, 0, self::GCM_IV_BYTES);
        $tag = substr($raw, self::GCM_IV_BYTES, self::GCM_TAG_BYTES);
        $cipherText = substr($raw, $minLength);

        $plain = openssl_decrypt($cipherText, self::CIPHER, $key, OPENSSL_RAW_DATA, $iv, $tag);
        if ($plain === false) {
            throw new \RuntimeException('Failed to decrypt MFA secret - wrong encryption key, or the stored value is corrupted.');
        }

        return $plain;
    }

    private static function encryptionKey(): string
    {
        $configured = Config::get('security.mfa_encryption_key');
        if (empty($configured) || $configured === 'CHANGEME') {
            throw new \RuntimeException(
                "MFA encryption key is not configured. Generate one with `openssl rand -base64 32` and set it as " .
                "config('security.mfa_encryption_key') in src/config/config.php before enabling MFA for any account."
            );
        }

        $key = base64_decode((string)$configured, true);
        if ($key === false || strlen($key) !== 32) {
            throw new \RuntimeException(
                "config('security.mfa_encryption_key') must be a base64-encoded 32-byte key, e.g. the output of " .
                "`openssl rand -base64 32`."
            );
        }

        return $key;
    }
}
