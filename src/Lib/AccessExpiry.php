<?php
declare(strict_types=1);

namespace VulnDash\Lib;

/**
 * Optional access end dates (2026-11-27), for clients whose service runs for
 * the validity of a CE+ certificate. Columns: organisations.expires_on and
 * users.expires_on (database/migrations/2026-11-27-add-access-expiry.sql).
 *
 * The rules, in one place:
 *   - The date is the LAST day of access, inclusive ("Access until"): with
 *     2027-03-01 the account works all of 1 March and is refused from 2 March
 *     (Europe/London, like the rest of the app).
 *   - A member of an organisation gets the EARLIER of its own date and the
 *     organisation's. No date on either = no end.
 *   - Admin accounts never expire, so an admin can't be locked out by a date.
 *   - Expired is treated like deactivated (UserRepository::ACCESS_NOT_EXPIRED_CONDITION
 *     sits beside ORG_ACTIVE_CONDITION): sign-in is refused, an open session
 *     ends on its next request, and no client emails are sent. The account
 *     itself is untouched, so changing or clearing the date (renewal) brings
 *     it straight back.
 *   - In the last WARN_DAYS days, the client sees a banner on every page
 *     (src/views/header.php), and admins are emailed once
 *     (src/Lib/AccessExpiryAlerts.php) - and once more when it ends.
 */
final class AccessExpiry
{
    public const WARN_DAYS = 30;

    /**
     * A date from an <input type="date"> (YYYY-MM-DD), or '' for none.
     *
     * @throws \RuntimeException for anything else
     */
    public static function parse(string $raw): ?string
    {
        $raw = trim($raw);
        if ($raw === '') {
            return null;
        }
        $d = \DateTimeImmutable::createFromFormat('!Y-m-d', $raw);
        if ($d === false || $d->format('Y-m-d') !== $raw || (int)$d->format('Y') < 2000 || (int)$d->format('Y') > 2100) {
            throw new \RuntimeException('Enter the access end date as a real date (for example 2027-03-01), or leave it blank for no end date.');
        }
        return $raw;
    }

    /** The date that actually applies: the earlier of the two, never for an admin. */
    public static function effective(?string $userDate, ?string $orgDate, bool $isAdmin): ?string
    {
        if ($isAdmin) {
            return null;
        }
        $dates = array_filter([$userDate, $orgDate], static fn ($d) => $d !== null && $d !== '');
        return $dates === [] ? null : min($dates);
    }

    public static function today(): string
    {
        return date('Y-m-d');
    }

    public static function isExpired(?string $date, ?string $today = null): bool
    {
        return $date !== null && ($today ?? self::today()) > $date;
    }

    /** Days of access left counting today as one: 1 on the last day, 0 once over. */
    public static function daysLeft(string $date, ?string $today = null): int
    {
        $from = new \DateTimeImmutable($today ?? self::today());
        $to = new \DateTimeImmutable($date);
        return max(0, (int)$from->diff($to)->format('%r%a') + 1);
    }

    /** Within the warning window (and not yet over). */
    public static function isEnding(?string $date, ?string $today = null): bool
    {
        return $date !== null && !self::isExpired($date, $today) && self::daysLeft($date, $today) <= self::WARN_DAYS;
    }

    /** What a client is told when their access has ended (login page). */
    public static function endedMessage(string $date): string
    {
        return 'Your access ended on ' . self::display($date) . '. To renew it, contact Plainsight Security.';
    }

    /** The banner shown to a client in the last WARN_DAYS days. */
    public static function endingMessage(string $date, ?string $today = null): string
    {
        $left = self::daysLeft($date, $today);
        return 'Your access ends ' . ($left === 1 ? 'today' : 'on ' . self::display($date) . ' (in ' . $left . ' days)')
            . '. To keep it, contact Plainsight Security about renewing.';
    }

    /** e.g. "Mon 1 Mar 2027". */
    public static function display(string $date): string
    {
        $ts = strtotime($date);
        return $ts === false ? $date : date('D j M Y', $ts);
    }
}
