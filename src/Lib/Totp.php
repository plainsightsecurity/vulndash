<?php
declare(strict_types=1);

namespace VulnDash\Lib;

/**
 * Pure-PHP TOTP (RFC 6238) / HOTP (RFC 4226) implementation - no Composer
 * dependency, consistent with the rest of this app (see bootstrap.php).
 * Compatible with Google Authenticator, Authy, 1Password, etc: SHA1,
 * 6 digits, 30-second step, which is what every mainstream authenticator
 * app assumes when it isn't told otherwise via the otpauth:// URI.
 *
 * This class is deliberately stateless and knows nothing about users,
 * encryption, or the database - see MfaService for secret storage/
 * encryption and the login-time verification workflow (lockouts, replay
 * protection via the last-used counter, etc). Keeping the RFC math
 * completely separate from that means it can be tested/reasoned about on
 * its own, against the published RFC 6238 Appendix B test vectors.
 */
final class Totp
{
    private const PERIOD = 30;
    private const DIGITS = 6;
    private const ALGO = 'sha1';

    /** 20 random bytes = 160 bits, the size RFC 4226 recommends for HMAC-SHA1. */
    public static function generateSecret(int $bytes = 20): string
    {
        return self::base32Encode(random_bytes($bytes));
    }

    /**
     * Builds the otpauth:// URI that authenticator apps read via QR code
     * (or manual entry of the URI's `secret` param). $issuer:$accountName
     * is what's shown as the entry's label in the app.
     */
    public static function provisioningUri(string $secret, string $accountName, string $issuer): string
    {
        $label = rawurlencode($issuer) . ':' . rawurlencode($accountName);
        $query = http_build_query([
            'secret'    => $secret,
            'issuer'    => $issuer,
            'algorithm' => 'SHA1',
            'digits'    => self::DIGITS,
            'period'    => self::PERIOD,
        ], '', '&', PHP_QUERY_RFC3986);

        return 'otpauth://totp/' . $label . '?' . $query;
    }

    /** RFC 4226 HOTP over a base32 secret, for a given counter value. */
    public static function codeAt(string $base32Secret, int $counter): string
    {
        $key = self::base32Decode($base32Secret);
        // 8-byte big-endian counter - two packed 32-bit big-endian words,
        // the high word always 0 here (see the class docblock: this
        // doesn't overflow within any realistic deployment lifetime).
        $binCounter = pack('N2', 0, $counter);
        $hash = hash_hmac(self::ALGO, $binCounter, $key, true);

        $offset = ord($hash[strlen($hash) - 1]) & 0x0F;
        $truncated = ((ord($hash[$offset]) & 0x7F) << 24)
            | ((ord($hash[$offset + 1]) & 0xFF) << 16)
            | ((ord($hash[$offset + 2]) & 0xFF) << 8)
            | (ord($hash[$offset + 3]) & 0xFF);

        $mod = 10 ** self::DIGITS;
        return str_pad((string)($truncated % $mod), self::DIGITS, '0', STR_PAD_LEFT);
    }

    /**
     * Checks a submitted code against a window of time steps either side of
     * now, to tolerate ordinary clock drift between the server and the
     * person's phone. Returns the matched counter (so the caller can record
     * it for replay protection - see MfaService::verifyLoginCode()) or null
     * if nothing in the window matches.
     *
     * $afterCounter, if given, rejects any counter at or before it - this
     * is the replay-protection hook: once a given 30-second code has been
     * accepted, that same code (or an older one still inside the window)
     * can never be accepted again.
     */
    public static function verify(
        string $base32Secret,
        string $code,
        int $window = 1,
        ?int $timestamp = null,
        ?int $afterCounter = null
    ): ?int {
        $code = preg_replace('/\s+/', '', $code) ?? '';
        if (!preg_match('/^\d{6}$/', $code)) {
            return null;
        }

        $timestamp = $timestamp ?? time();
        $counter = intdiv($timestamp, self::PERIOD);

        for ($i = -$window; $i <= $window; $i++) {
            $testCounter = $counter + $i;
            if ($testCounter < 0 || ($afterCounter !== null && $testCounter <= $afterCounter)) {
                continue;
            }
            if (hash_equals(self::codeAt($base32Secret, $testCounter), $code)) {
                return $testCounter;
            }
        }

        return null;
    }

    /** RFC 4648 base32 (no padding) - all this app's secrets are generated internally, so a fixed-length unpadded encoding is fine on both ends. */
    public static function base32Encode(string $data): string
    {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $bits = '';
        foreach (str_split($data) as $char) {
            $bits .= str_pad(decbin(ord($char)), 8, '0', STR_PAD_LEFT);
        }

        $output = '';
        foreach (str_split($bits, 5) as $chunk) {
            if (strlen($chunk) < 5) {
                $chunk = str_pad($chunk, 5, '0', STR_PAD_RIGHT);
            }
            $output .= $alphabet[bindec($chunk)];
        }

        return $output;
    }

    public static function base32Decode(string $data): string
    {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $data = strtoupper((string)preg_replace('/[^A-Za-z2-7]/', '', $data));

        $bits = '';
        foreach (str_split($data) as $char) {
            $pos = strpos($alphabet, $char);
            if ($pos === false) {
                continue;
            }
            $bits .= str_pad(decbin($pos), 5, '0', STR_PAD_LEFT);
        }

        $output = '';
        foreach (str_split($bits, 8) as $byte) {
            if (strlen($byte) === 8) {
                $output .= chr(bindec($byte));
            }
        }

        return $output;
    }
}
