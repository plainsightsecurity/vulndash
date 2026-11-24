<?php
declare(strict_types=1);

namespace VulnDash\Lib;

/**
 * State/bookkeeping for the opt-in "new activity" email nudges sent by
 * scripts/send_notifications.php. Deliberately thin: it decides *who is due*
 * for a nudge and records *that one was sent*. Whether a due account actually
 * has anything new to see is a scope question answered by
 * VulnerabilityRepository::scopeHasNewActivity() (the single tag-scoping choke
 * point), and the email itself is built/sent by Mailer - this class touches
 * neither, so it can't accidentally leak scoped data or email content.
 *
 * The notification state lives as three columns on `users`
 * (notify_frequency / notify_watermark_id / notify_last_sent_at - see
 * database/migrations/2026-07-add-notification-preferences.sql); this class is
 * just the read/write surface the cron uses for them. The opt-in itself
 * (notify_frequency) is written from public/preferences.php via
 * UserRepository::setNotifyFrequency(), not here.
 */
class NotificationRepository
{
    // Cadence is enforced as a MINIMUM spacing between sends, measured off
    // notify_last_sent_at. Both intervals are set slightly UNDER the nominal
    // period so a cron that fires at a fixed clock time each day never skips a
    // period by a few seconds of drift (a "daily" account whose last send was
    // 23h59m ago is treated as due on today's run rather than waiting a whole
    // further day). The gap between the nominal period and the guard also means
    // no account is ever emailed more than once per intended period.
    private const DAILY_MIN_HOURS  = 23;    // ~1 day
    private const WEEKLY_MIN_HOURS = 156;   // 6.5 days

    /**
     * Opted-in, active accounts whose cadence has elapsed and who are therefore
     * eligible for a nudge on this run - subject to actually having new activity
     * in scope, which the caller checks per account. Deactivated accounts
     * (is_active = 0) are never returned: a suspended login shouldn't be emailed.
     *
     * notify_watermark_id may be NULL only for the window between a schema
     * migration adding the column and the account next opting in; opting in
     * always seeds it (UserRepository::setNotifyFrequency), so in practice an
     * opted-in account has a real watermark. The caller coalesces NULL to a
     * safe floor regardless.
     *
     * @return array<int, array{id:int, username:string, email:string,
     *         is_admin:int, notify_frequency:string, notify_watermark_id:?int}>
     */
    public static function dueRecipients(): array
    {
        $pdo = Database::getConnection();
        // One row per eligible account. The cadence gate is expressed against
        // NOW() so it uses the same Europe/London session zone as every other
        // write (see Database::getConnection()). Named placeholders are
        // single-use (non-emulated prepares) - two distinct names for the two
        // interval bounds.
        $stmt = $pdo->prepare(
            "SELECT id, username, email, is_admin, notify_frequency, notify_watermark_id
             FROM users
             WHERE is_active = 1 AND " . UserRepository::ORG_ACTIVE_CONDITION . "
               AND notify_frequency <> 'off'
               AND (
                     (notify_frequency = 'daily'
                       AND (notify_last_sent_at IS NULL
                            OR notify_last_sent_at < NOW() - INTERVAL :daily_hours HOUR))
                  OR (notify_frequency = 'weekly'
                       AND (notify_last_sent_at IS NULL
                            OR notify_last_sent_at < NOW() - INTERVAL :weekly_hours HOUR))
                   )
             ORDER BY id"
        );
        $stmt->execute([
            'daily_hours'  => self::DAILY_MIN_HOURS,
            'weekly_hours' => self::WEEKLY_MIN_HOURS,
        ]);

        $rows = [];
        foreach ($stmt->fetchAll() as $r) {
            $rows[] = [
                'id'                  => (int)$r['id'],
                'username'            => (string)$r['username'],
                'email'               => (string)$r['email'],
                'is_admin'            => (int)$r['is_admin'],
                'notify_frequency'    => (string)$r['notify_frequency'],
                'notify_watermark_id' => $r['notify_watermark_id'] !== null ? (int)$r['notify_watermark_id'] : null,
            ];
        }
        return $rows;
    }

    /**
     * Record that a nudge was just sent to $userId: advance the cadence clock
     * and move the watermark up to $watermarkId (the max host_detections.id
     * considered at send time), so the same batch of findings is never the
     * reason for a second email. Called only after Mailer confirms the send;
     * a failed send leaves both untouched so the account is retried next run.
     */
    public static function recordSent(int $userId, int $watermarkId): void
    {
        Database::getConnection()
            ->prepare('UPDATE users SET notify_last_sent_at = NOW(), notify_watermark_id = :wm WHERE id = :id')
            ->execute(['wm' => $watermarkId, 'id' => $userId]);
    }
}
