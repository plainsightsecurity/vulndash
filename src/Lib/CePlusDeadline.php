<?php
declare(strict_types=1);

namespace VulnDash\Lib;

/**
 * The Cyber Essentials Plus 14-day patch clock - the one place its rule
 * lives, so the list, detail page, dashboard and exports can't disagree
 * about what "overdue" means.
 *
 * Cyber Essentials requires high/critical updates to be applied within 14
 * days of the vendor releasing them, so the clock runs from the vendor's
 * patch date:
 *
 *     due = clock start + PATCH_WINDOW_DAYS, overdue once now > due
 *
 * CLOCK START (2026-11-04, decided after checking live data):
 *
 *   - knowledge_base.patch_published_date - Qualys's PATCH_PUBLISHED_DATE,
 *     when the fix was released. This is what an assessment counts from.
 *     The QID's own published date can be far later: two Python QIDs on
 *     this subscription were published by Qualys in June 2026 for a patch
 *     released in April 2023, so counting from that showed them comfortably
 *     inside the window when they were years overdue.
 *   - Otherwise knowledge_base.published_datetime, when Qualys published the
 *     QID - the only date there was before the patch date was captured, and
 *     still the fallback for a QID the KB sync hasn't refreshed yet. Used
 *     silently, with no "estimated" marker (decision 2026-11-04).
 *   - No clock at all when Qualys marks the QID PATCHABLE 0: there's no
 *     patch to be late applying. Without this, a CE+ failure with no fix yet
 *     (QID 389141, a PHP RCE whose title doesn't say "Zero Day", so
 *     CvssCalculator still counts it) went "overdue" 14 days after Qualys
 *     published it. The finding stays a CE+ failure - end-of-life software
 *     is typically unpatchable too and genuinely fails CE+ - only the
 *     countdown goes.
 *
 * CLOCK_START_SQL and clockStartUtc() are the same rule written for SQL and
 * PHP; change both together.
 *
 * Only CE+ failures get a clock. A QID currently titled as a zero-day is
 * never one (CvssCalculator excludes it). A FORMER zero-day keeps its
 * original published date; if Qualys gives it a patch date that's now used
 * instead, otherwise it may show overdue straight away - accepted as rare
 * (decision 2026-11-04).
 *
 * Both dates are stored in UTC (see QualysApiClient::toMysqlDatetime()),
 * so every comparison here and in SQL is done in UTC. No usable start date
 * means no clock - shown as unknown, never as overdue.
 */
final class CePlusDeadline
{
    public const PATCH_WINDOW_DAYS = 14;

    /**
     * The clock's start date as a SQL expression over knowledge_base (kb):
     * NULL - no clock - when Qualys marks the QID unpatchable, otherwise the
     * patch date, else the published date. Used by VulnerabilityRepository
     * for the overdue filter and the "CE+ due" sort. Mirrors clockStartUtc().
     */
    public const CLOCK_START_SQL = '(CASE WHEN kb.patchable = 0 THEN NULL ELSE COALESCE(kb.patch_published_date, kb.published_datetime) END)';

    /**
     * The UTC instant a clock must have started before to be overdue now -
     * bound into SQL by VulnerabilityRepository's ce_overdue_only filter as
     * "CLOCK_START_SQL < :cutoff", the same comparison status() makes below.
     */
    public static function overdueCutoffUtc(?\DateTimeImmutable $now = null): string
    {
        $now = ($now ?? new \DateTimeImmutable('now'))->setTimezone(new \DateTimeZone('UTC'));
        return $now->modify('-' . self::PATCH_WINDOW_DAYS . ' days')->format('Y-m-d H:i:s');
    }

    /**
     * The clock's start date (UTC) for a row carrying the knowledge_base
     * fields patchable, patch_published_date and published_datetime - PHP
     * twin of CLOCK_START_SQL. A row without a patchable key at all is
     * treated as patchable, so a caller that didn't select it keeps a clock
     * rather than silently losing one.
     */
    public static function clockStartUtc(array $row): ?string
    {
        if (array_key_exists('patchable', $row) && $row['patchable'] !== null && (int)$row['patchable'] === 0) {
            return null;
        }
        foreach (['patch_published_date', 'published_datetime'] as $key) {
            if (isset($row[$key]) && $row[$key] !== '') {
                return (string)$row[$key];
            }
        }
        return null;
    }

    /**
     * The clock for one detection row (host_detections + knowledge_base
     * columns, as the repository returns them), or null when it has none.
     *
     * @return array{due: \DateTimeImmutable, overdue: bool, days: int}|null
     */
    public static function forRow(array $row, ?\DateTimeImmutable $now = null): ?array
    {
        return self::status(!empty($row['is_ce_plus_fail']), self::clockStartUtc($row), $now);
    }

    /**
     * The clock for one detection, or null when it has none (not a CE+
     * failure, or no start date - see clockStartUtc()).
     *
     * 'overdue' is exact to the second, matching the SQL cutoff. 'days' is
     * whole CALENDAR days (UK time) between today and the due date - days
     * past it when overdue, days to go otherwise - so the number always
     * agrees with the due date shown beside it. Elapsed-time rounding didn't:
     * a due date of 19 Oct read "Overdue 17d" on 4 Nov. 0 means the due
     * date is today; the labels below say so in words.
     *
     * @return array{due: \DateTimeImmutable, overdue: bool, days: int}|null
     *         'due' is in Europe/London, ready to format for display
     */
    public static function status(bool $isCePlusFail, ?string $clockStartUtc, ?\DateTimeImmutable $now = null): ?array
    {
        if (!$isCePlusFail || $clockStartUtc === null || $clockStartUtc === '') {
            return null;
        }

        try {
            $start = new \DateTimeImmutable($clockStartUtc, new \DateTimeZone('UTC'));
        } catch (\Exception $e) {
            return null;
        }

        $london = new \DateTimeZone('Europe/London');
        $now = ($now ?? new \DateTimeImmutable('now'))->setTimezone($london);
        $due = $start->modify('+' . self::PATCH_WINDOW_DAYS . ' days')->setTimezone($london);
        $overdue = $now > $due;

        // Diffed as bare dates pinned to UTC, so a BST/GMT change between the
        // two can't turn a 23- or 25-hour day into an off-by-one.
        $utc = new \DateTimeZone('UTC');
        $calendarDays = (new \DateTimeImmutable($now->format('Y-m-d'), $utc))
            ->diff(new \DateTimeImmutable($due->format('Y-m-d'), $utc))
            ->days;

        return [
            'due'     => $due,
            'overdue' => $overdue,
            'days'    => (int)$calendarDays,
        ];
    }

    /** Short label for a list cell or PDF row: "Overdue 12d" / "5d left" / "Overdue today" / "Due today". */
    public static function shortLabel(array $status): string
    {
        if ($status['days'] === 0) {
            return $status['overdue'] ? 'Overdue today' : 'Due today';
        }
        return $status['overdue'] ? 'Overdue ' . $status['days'] . 'd' : $status['days'] . 'd left';
    }

    /** Badge wording for the detail page: "Patch overdue · 12 days" / "Patch due in 5 days". */
    public static function longLabel(array $status): string
    {
        if ($status['days'] === 0) {
            return $status['overdue'] ? 'Patch overdue · due today' : 'Patch due today';
        }
        $n = $status['days'] . ' day' . ($status['days'] === 1 ? '' : 's');
        return $status['overdue'] ? 'Patch overdue · ' . $n : 'Patch due in ' . $n;
    }
}
