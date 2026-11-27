<?php
declare(strict_types=1);

namespace VulnDash\Lib;

/**
 * Optional access end dates on TAGS (2026-11-27), for clients whose service
 * runs for the validity of a CE+ certificate. Column tags.expires_on
 * (database/migrations/2026-11-27-tag-access-expiry.sql). It's on the tag,
 * not the account, because an MSP account sees several clients' tags and one
 * client lapsing mustn't take the others away.
 *
 * The rules, in one place:
 *   - The date is the LAST day of access, inclusive ("Access until"): with
 *     2027-03-01 the tag's assets are visible all of 1 March and gone from
 *     2 March (Europe/London, like the rest of the app).
 *   - From then on, for every NON-ADMIN account the tag simply drops out of
 *     what it can see - whether it came from the account's own tags or its
 *     organisation's. UserRepository::LIVE_TAGS_SQL is the one filter, used
 *     for the session's scope (so every page, export and the fail-closed
 *     buildTagScopeJoin() follow) and for notification/KEV emails. Admins
 *     still see everything; syncs and Qualys are untouched.
 *   - Nobody is locked out: an account whose tags have all ended still signs
 *     in, sees no data, and is told why.
 *   - Clients see a notice for a tag in its last WARN_DAYS days, and for
 *     ENDED_NOTICE_DAYS after it ends (always, while they have no live tag
 *     left). Admins are emailed once in the warning window and once when it
 *     ends (AccessExpiryAlerts).
 *   - Renewal = move the date on or clear it; access returns at once.
 */
final class AccessExpiry
{
    public const WARN_DAYS = 30;
    public const ENDED_NOTICE_DAYS = 30;

    /**
     * WHERE condition on a tags table aliased $alias: "this tag's access
     * hasn't ended". CURDATE() is Europe/London (Database.php pins the session
     * time zone), matching today().
     */
    public static function liveCondition(string $alias): string
    {
        return "({$alias}.expires_on IS NULL OR {$alias}.expires_on >= CURDATE())";
    }

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

    /** Days since access ended: 1 on the first day without it. */
    public static function daysSinceEnded(string $date, ?string $today = null): int
    {
        $from = new \DateTimeImmutable($date);
        $to = new \DateTimeImmutable($today ?? self::today());
        return max(0, (int)$from->diff($to)->format('%r%a'));
    }

    /** Within the warning window (and not yet over). */
    public static function isEnding(?string $date, ?string $today = null): bool
    {
        return $date !== null && !self::isExpired($date, $today) && self::daysLeft($date, $today) <= self::WARN_DAYS;
    }

    /**
     * The client-facing notice for one tag, or null if it needs none.
     * $hasLiveTags: whether the account can still see anything - with nothing
     * left, an ended tag is explained however long ago it ended.
     */
    public static function notice(string $tagName, ?string $date, bool $hasLiveTags, ?string $today = null): ?string
    {
        if ($date === null) {
            return null;
        }
        if (self::isExpired($date, $today)) {
            if ($hasLiveTags && self::daysSinceEnded($date, $today) > self::ENDED_NOTICE_DAYS) {
                return null;
            }
            return "Access to {$tagName} ended on " . self::display($date) . '. To renew it, contact Plainsight Security.';
        }
        if (!self::isEnding($date, $today)) {
            return null;
        }
        $left = self::daysLeft($date, $today);
        return "Access to {$tagName} ends " . ($left === 1 ? 'today' : 'on ' . self::display($date) . " (in {$left} days)")
            . '. To keep it, contact Plainsight Security about renewing.';
    }

    /** e.g. "Mon 1 Mar 2027". */
    public static function display(string $date): string
    {
        $ts = strtotime($date);
        return $ts === false ? $date : date('D j M Y', $ts);
    }
}
