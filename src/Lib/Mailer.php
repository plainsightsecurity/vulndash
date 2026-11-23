<?php
declare(strict_types=1);

namespace VulnDash\Lib;

/**
 * Thin wrapper around the Resend API (https://resend.com/docs/api-reference/emails/send-email)
 * for the two transactional emails this app sends: "create your password"
 * (new admin-created accounts - see UserRepository::createUser()) and
 * "reset your password" (self-service forgot-password, or an admin
 * resending the link from Manage Users). No SDK/Composer dependency, in
 * keeping with the rest of the app (see src/bootstrap.php) - just a single
 * cURL POST to /emails, the same shape as scripts/lib/QualysApiClient.php's
 * calls to Qualys.
 *
 * Fails closed, never throws: a missing/placeholder API key or a failed
 * Resend request logs to error_log and returns false rather than
 * interrupting the calling flow - account creation itself must still
 * succeed even if the follow-up email doesn't go out. Callers use the
 * boolean to flash an appropriate message (the admin UI's "Email password
 * reset link" action is the fallback if a send ever fails).
 */
final class Mailer
{
    /**
     * The initial "create your password" email for a brand new,
     * admin-created account - the account has no password its owner
     * knows yet (UserRepository::createUser() sets an unusable random
     * one) until this link is used on public/reset_password.php.
     */
    public static function sendPasswordSetupEmail(string $toEmail, string $toName, string $link): bool
    {
        $appName = (string)(Config::get('app.name') ?? 'VulnDash');
        $subject = "Set up your {$appName} password";

        $html = self::wrapHtml(
            '<p>Hi ' . self::h($toName) . ',</p>'
            . '<p>An account has been created for you on <strong>' . self::h($appName) . '</strong>. '
            . 'Click the button below to set a password and sign in:</p>'
            . self::button($link, 'Set your password')
            . '<p style="color:#5B6472;font-size:13px;">Or copy and paste this link into your browser:<br>'
            . '<span style="word-break:break-all;">' . self::h($link) . '</span></p>'
            . '<p style="color:#5B6472;font-size:13px;">This link expires in 7 days. '
            . "If you weren't expecting this, you can safely ignore it.</p>"
        );

        $text = "Hi {$toName},\n\n"
            . "An account has been created for you on {$appName}. Set a password using the link below:\n\n"
            . "{$link}\n\n"
            . "This link expires in 7 days. If you weren't expecting this, you can safely ignore it.\n";

        return self::send($toEmail, $toName, $subject, $html, $text);
    }

    /**
     * "Reset your password" email - either self-requested from
     * public/forgot_password.php, or sent on demand by an admin from
     * Manage Users ("Email password reset link").
     */
    public static function sendPasswordResetEmail(string $toEmail, string $toName, string $link): bool
    {
        $appName = (string)(Config::get('app.name') ?? 'VulnDash');
        $subject = "Reset your {$appName} password";

        $html = self::wrapHtml(
            '<p>Hi ' . self::h($toName) . ',</p>'
            . '<p>We received a request to reset your <strong>' . self::h($appName) . '</strong> password. '
            . 'Click the button below to choose a new one:</p>'
            . self::button($link, 'Reset your password')
            . '<p style="color:#5B6472;font-size:13px;">Or copy and paste this link into your browser:<br>'
            . '<span style="word-break:break-all;">' . self::h($link) . '</span></p>'
            . '<p style="color:#5B6472;font-size:13px;">This link expires in 1 hour. '
            . "If you didn't request this, you can safely ignore it - your password won't be changed.</p>"
        );

        $text = "Hi {$toName},\n\n"
            . "We received a request to reset your {$appName} password. Use the link below to choose a new one:\n\n"
            . "{$link}\n\n"
            . "This link expires in 1 hour. If you didn't request this, you can safely ignore it - your password won't be changed.\n";

        return self::send($toEmail, $toName, $subject, $html, $text);
    }

    /**
     * Opt-in "new activity" nudge (scripts/send_notifications.php). By design
     * this email carries NO vulnerability information whatsoever - no counts,
     * asset names, QIDs, CVEs or severities - only that there is new activity to
     * review, plus a link to sign in. Email is not an encrypted-at-rest channel,
     * so all security-posture detail deliberately stays behind authentication on
     * the TLS-served dashboard; the message's only job is to bring the recipient
     * back to look. $signInUrl is the app's own login page (built from
     * app.base_url by the caller), never a token or deep link.
     */
    public static function sendActivityDigestEmail(string $toEmail, string $toName, string $signInUrl): bool
    {
        $appName = (string)(Config::get('app.name') ?? 'VulnDash');
        $subject = "New activity on your {$appName} dashboard";

        $html = self::wrapHtml(
            '<p>Hi ' . self::h($toName) . ',</p>'
            . '<p>There\'s new activity on your <strong>' . self::h($appName) . '</strong> dashboard '
            . 'since you were last notified. Sign in to review it:</p>'
            . self::button($signInUrl, 'Sign in to review')
            . '<p style="color:#5B6472;font-size:13px;">Or copy and paste this link into your browser:<br>'
            . '<span style="word-break:break-all;">' . self::h($signInUrl) . '</span></p>'
            . '<p style="color:#5B6472;font-size:13px;">You\'re receiving this because email notifications are '
            . 'switched on for your account. You can change how often you get these, or turn them off, '
            . 'under Preferences once you\'re signed in.</p>'
        );

        $text = "Hi {$toName},\n\n"
            . "There's new activity on your {$appName} dashboard since you were last notified. "
            . "Sign in to review it:\n\n"
            . "{$signInUrl}\n\n"
            . "You're receiving this because email notifications are switched on for your account. "
            . "You can change how often you get these, or turn them off, under Preferences once you're signed in.\n";

        return self::send($toEmail, $toName, $subject, $html, $text);
    }

    private static function button(string $href, string $label): string
    {
        return '<p><a href="' . self::h($href) . '" '
            . 'style="display:inline-block;padding:0.65em 1.3em;background:#167A70;color:#ffffff;'
            . 'border-radius:6px;text-decoration:none;font-weight:600;">' . self::h($label) . '</a></p>';
    }

    private static function wrapHtml(string $bodyHtml): string
    {
        return '<!DOCTYPE html><html><body style="font-family:Arial,Helvetica,sans-serif;font-size:15px;color:#1b1f24;line-height:1.5;max-width:480px;">'
            . $bodyHtml
            . '</body></html>';
    }

    private static function h(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
    }

    /**
     * Builds the "Display Name <email@example.com>" recipient format
     * Resend expects, stripping characters that would break that format
     * (angle brackets, quotes, line breaks) out of the display name rather
     * than escaping them - a username is never expected to contain these,
     * so simply dropping them is enough to keep the field well-formed.
     */
    private static function formatRecipient(string $email, string $name): string
    {
        $name = trim((string)preg_replace('/[\r\n<>"]+/', '', $name));
        return $name !== '' ? "{$name} <{$email}>" : $email;
    }

    /**
     * @return bool true if Resend accepted the request (HTTP 2xx). false
     *         on any failure - unconfigured API key, network error, or a
     *         non-2xx response - always logged to error_log with enough
     *         detail to diagnose, never thrown to the caller or shown to
     *         the recipient.
     */
    private static function send(string $toEmail, string $toName, string $subject, string $html, string $text): bool
    {
        $apiKey = (string)(Config::get('resend.api_key') ?? '');
        if ($apiKey === '' || $apiKey === 'CHANGEME') {
            error_log("Mailer: resend.api_key is not configured in src/config/config.php - email not sent (subject: \"{$subject}\", to: {$toEmail})");
            return false;
        }

        $fromEmail = (string)(Config::get('resend.from_email') ?? 'dashboard@plainsightsecurity.co.uk');
        $fromName  = (string)(Config::get('resend.from_name') ?? 'VulnDash');

        // Only ever overridden for local/sandbox testing against a fake
        // Resend server - production config has no resend.api_base key, so
        // this always resolves to the real API there.
        $apiBase = rtrim((string)(Config::get('resend.api_base') ?? 'https://api.resend.com'), '/');

        $payload = [
            'from'    => self::formatRecipient($fromEmail, $fromName),
            'to'      => [self::formatRecipient($toEmail, $toName)],
            'subject' => $subject,
            'html'    => $html,
            'text'    => $text,
        ];

        $ch = curl_init("{$apiBase}/emails");
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST           => true,
            CURLOPT_HTTPHEADER     => [
                'Authorization: Bearer ' . $apiKey,
                'Content-Type: application/json',
            ],
            CURLOPT_POSTFIELDS => json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
            CURLOPT_TIMEOUT    => 15,
        ]);

        $response  = curl_exec($ch);
        $httpCode  = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlErrNo = curl_errno($ch);
        $curlErr   = curl_error($ch);
        curl_close($ch);

        if ($response === false || $curlErrNo !== 0) {
            error_log("Mailer: cURL error sending to {$toEmail} (subject: \"{$subject}\"): {$curlErr}");
            return false;
        }

        if ($httpCode < 200 || $httpCode >= 300) {
            error_log("Mailer: Resend API returned HTTP {$httpCode} for {$toEmail} (subject: \"{$subject}\"): {$response}");
            return false;
        }

        return true;
    }
}
