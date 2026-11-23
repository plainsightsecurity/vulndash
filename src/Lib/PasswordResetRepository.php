<?php
declare(strict_types=1);

namespace VulnDash\Lib;

/**
 * Tokens behind the emailed "set your password" links - both the initial
 * one for a brand new admin-created account (purpose = 'setup') and the
 * forgot-password / admin-resend one for an existing account
 * (purpose = 'reset'). Both purposes are consumed by the same
 * public/reset_password.php page; purpose only changes which email copy
 * Mailer sends and how long the link stays valid.
 *
 * Same selector/validator split as TrustedDeviceRepository/
 * user_trusted_devices (see database/migrations/2026-07-add-mfa.sql for
 * the full rationale): `selector` is an indexed lookup key with nothing
 * secret about it on its own, `validator` is never stored - only
 * sha256(validator) is, in token_hash - so a stolen database dump alone
 * can't be replayed as a valid reset link.
 */
final class PasswordResetRepository
{
    public const PURPOSE_SETUP = 'setup';
    public const PURPOSE_RESET = 'reset';

    // A brand new account's setup link gets a week - it's the only way in
    // until it's used, so it needs enough slack for someone to get to it.
    // A forgot-password link is much shorter-lived since the account
    // already has a working password the person can fall back to.
    private const TTL_SECONDS_SETUP = 7 * 86400;
    private const TTL_SECONDS_RESET = 3600;

    /**
     * Issues a fresh token for $userId and returns the opaque
     * `selector.validator` string to embed in the emailed link - never
     * stored anywhere itself, only its hash is (see class docblock).
     * Invalidates any other outstanding, unused token for this user first
     * (regardless of purpose), so at most one emailed link is ever live
     * for an account at a time - an old "create your password" email
     * can't be replayed alongside a freshly requested reset, or vice versa.
     */
    public static function issue(int $userId, string $purpose): string
    {
        self::invalidateForUser($userId);

        $selector  = bin2hex(random_bytes(12));  // 24 hex chars, indexed lookup key
        $validator = bin2hex(random_bytes(32));  // 64 hex chars, never stored - only its hash is
        $ttl = $purpose === self::PURPOSE_SETUP ? self::TTL_SECONDS_SETUP : self::TTL_SECONDS_RESET;

        Database::getConnection()->prepare(
            'INSERT INTO password_reset_tokens (user_id, selector, token_hash, purpose, expires_at, requested_ip)
             VALUES (:user_id, :selector, :hash, :purpose, :expires, :ip)'
        )->execute([
            'user_id'  => $userId,
            'selector' => $selector,
            'hash'     => hash('sha256', $validator),
            'purpose'  => $purpose,
            'expires'  => date('Y-m-d H:i:s', time() + $ttl),
            'ip'       => $_SERVER['REMOTE_ADDR'] ?? null,
        ]);

        return $selector . '.' . $validator;
    }

    /**
     * Looks up a `selector.validator` token from an emailed link. Returns
     * the token row (id, user_id, purpose) if - and only if - it exists,
     * is unexpired, and hasn't already been used, and the validator's hash
     * matches what's stored. Returns null for anything else (malformed
     * token, wrong validator, expired, already used) without
     * distinguishing which - same fail-closed, no-information-leak
     * approach as TrustedDeviceRepository::isTrusted().
     *
     * @return array{id: int, user_id: int, purpose: string}|null
     */
    public static function validate(string $token): ?array
    {
        if (!str_contains($token, '.')) {
            return null;
        }

        [$selector, $validator] = explode('.', $token, 2);
        if ($selector === '' || $validator === '') {
            return null;
        }

        $stmt = Database::getConnection()->prepare(
            'SELECT id, user_id, token_hash, purpose FROM password_reset_tokens
             WHERE selector = :selector AND used_at IS NULL AND expires_at > NOW() LIMIT 1'
        );
        $stmt->execute(['selector' => $selector]);
        $row = $stmt->fetch();

        if (!$row || !hash_equals($row['token_hash'], hash('sha256', $validator))) {
            return null;
        }

        return [
            'id'      => (int)$row['id'],
            'user_id' => (int)$row['user_id'],
            'purpose' => $row['purpose'],
        ];
    }

    /** Marks one token as spent - called once the new password has actually been saved. */
    public static function consume(int $tokenId): void
    {
        Database::getConnection()->prepare('UPDATE password_reset_tokens SET used_at = NOW() WHERE id = :id')
            ->execute(['id' => $tokenId]);
    }

    /** Marks every outstanding, unused token for a user as spent - see issue()'s docblock for why. */
    public static function invalidateForUser(int $userId): void
    {
        Database::getConnection()->prepare(
            'UPDATE password_reset_tokens SET used_at = NOW() WHERE user_id = :id AND used_at IS NULL'
        )->execute(['id' => $userId]);
    }
}
