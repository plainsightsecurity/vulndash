<?php
declare(strict_types=1);

namespace VulnDash\Lib;

/**
 * Whether a host would pass Cyber Essentials Plus - the one home of the
 * host-level rule behind the CE+ readiness page (public/ce_readiness.php),
 * built on CePlusDeadline's per-finding 14-day clock so the two can't
 * disagree about what "overdue" means.
 *
 * STATUS TODAY (decision 2026-11-10). From a host's open CE+ failures
 * (hd.is_ce_plus_fail = 1 - CVSS 7.0+, zero-days already excluded by
 * CvssCalculator):
 *
 *   - FAIL when it has any end-of-life finding (see EOL below), or any of
 *     its other CE+ failures is
 *       - overdue: patch released more than 14 days ago;
 *       - undated: patchable, but no patch or published date to start a
 *         clock from. Fail-loud: "unknown" must never read as "fine".
 *   - AT RISK when it has CE+ failures but every one is still inside its
 *     14-day window. Passes today; fails once the earliest due date passes.
 *   - PASS when it has none that count.
 *
 * Findings with no vendor fix (Qualys PATCHABLE 0) don't count towards any
 * of these (correction 2026-11-10): CE+ fails a host for not applying a
 * patch within 14 days of release, and with no patch released there is
 * nothing to apply. Same reasoning as CePlusDeadline giving them no clock.
 * They're still shown on the page (the "No fix" column) for information.
 *
 * EOL (decision 2026-11-10): end-of-life software always fails - CE
 * requires unsupported software to be removed, whatever its CVSS score and
 * whether or not Qualys marks it patchable. Recognised by Qualys's title
 * convention ("EOL/Obsolete Software: ...", "EOL/Obsolete Operating System:
 * ..."), matched only through EOL_TITLE_SQL / isEolTitle() below. So an EOL
 * finding fails the host even when it's below 7.0 and so not a CE+ failure
 * in hd.is_ce_plus_fail terms. EOL findings are counted on their own
 * (eol_count) and left out of every other count, so a host's EOL findings
 * are never double-counted or given a patch deadline.
 *
 * Hidden findings COUNT (decision 2026-11-10): the assessment runs in
 * Qualys, which never sees a dashboard hide, so readiness must show what the
 * assessor will see. Callers read with hides ignored.
 *
 * A host whose agent isn't reporting (StaleAgent) keeps the status of its
 * last known data and is flagged alongside it, not reclassified (decision
 * 2026-11-10).
 *
 * PROJECTION to an assessment date D (tags.ce_assessment_date, a UK
 * calendar day): an at-risk host is projected to fail on D when its earliest
 * due date falls on or before D. "On D" counts as failing deliberately -
 * the assessor may test that afternoon, after the deadline. A failing host
 * stays failing (nothing in the data says it will be patched); a passing
 * host stays passing (new findings can't be predicted). Both caveats are
 * spelt out on the page.
 *
 * Input rows are VulnerabilityRepository::getCePlusReadinessHosts() rows.
 */
final class CePlusReadiness
{
    /**
     * SQL condition over knowledge_base (kb) matching an end-of-life QID.
     * A literal, not a bound parameter, so it can appear several times in
     * one native prepare (see Database.php). The column's utf8mb4_0900_ai_ci
     * collation makes LIKE case-insensitive. Twin of isEolTitle(); change
     * both together.
     */
    public const EOL_TITLE_SQL = "kb.title LIKE '%EOL/Obsolete%'";

    public const FAIL    = 'fail';
    public const AT_RISK = 'at_risk';
    public const PASS    = 'pass';

    private const LABELS = [
        self::FAIL    => 'Fail',
        self::AT_RISK => 'At risk',
        self::PASS    => 'Pass',
    ];

    /** True for an end-of-life QID title - PHP twin of EOL_TITLE_SQL. */
    public static function isEolTitle(?string $title): bool
    {
        return $title !== null && stripos($title, 'EOL/Obsolete') !== false;
    }

    /** Count of the host's findings that fail it today (EOL + overdue + no date). */
    public static function blockingCount(array $row): int
    {
        return (int)$row['eol_count'] + (int)$row['overdue_count'] + (int)$row['no_date_count'];
    }

    public static function status(array $row): string
    {
        if (self::blockingCount($row) > 0) {
            return self::FAIL;
        }
        // No-fix findings don't count - see the class docblock.
        return (int)$row['ce_total'] - (int)$row['no_fix_count'] > 0 ? self::AT_RISK : self::PASS;
    }

    /**
     * The earliest deadline among the host's in-window findings - when an
     * at-risk host tips into failing - as CePlusDeadline::status() returns
     * it, or null when the host has no in-window findings.
     *
     * @return array{due: \DateTimeImmutable, overdue: bool, days: int}|null
     */
    public static function nextDeadline(array $row, ?\DateTimeImmutable $now = null): ?array
    {
        $start = $row['next_clock_start'] ?? null;
        return CePlusDeadline::status(true, $start !== null ? (string)$start : null, $now);
    }

    /**
     * Status on assessment day $assessmentDate ('Y-m-d', UK calendar day).
     * See the class docblock for why each status projects as it does.
     */
    public static function projectedStatus(array $row, string $assessmentDate, ?\DateTimeImmutable $now = null): string
    {
        $status = self::status($row);
        if ($status !== self::AT_RISK) {
            return $status;
        }
        $next = self::nextDeadline($row, $now);
        if ($next === null) {
            return $status;
        }
        // Both sides are UK calendar dates as 'Y-m-d', so a string compare is a date compare.
        return $next['due']->format('Y-m-d') <= $assessmentDate ? self::FAIL : self::AT_RISK;
    }

    public static function label(string $status): string
    {
        return self::LABELS[$status] ?? 'Unknown';
    }

    /**
     * Badge class for a status, reusing existing styles: the CE+ red for a
     * fail, the "treat with caution" amber for at risk, the green active
     * badge for a pass.
     */
    public static function badgeClass(string $status): string
    {
        return match ($status) {
            self::FAIL    => 'badge-ce-fail',
            self::AT_RISK => 'sev-medium',
            default       => 'badge-active',
        };
    }

    /**
     * A tag's assessment date as a validated 'Y-m-d' string, or null when
     * $value isn't a real calendar date - so a hand-posted "2026-02-30" or
     * free text is rejected rather than silently rolled over by PHP.
     */
    public static function parseDate(?string $value): ?string
    {
        $value = trim((string)$value);
        if ($value === '' || !preg_match('/^\d{4}-\d{2}-\d{2}$/', $value)) {
            return null;
        }
        $d = \DateTimeImmutable::createFromFormat('!Y-m-d', $value, new \DateTimeZone('Europe/London'));
        return ($d !== false && $d->format('Y-m-d') === $value) ? $value : null;
    }

    /** Today as a UK calendar date, 'Y-m-d'. */
    public static function todayUk(?\DateTimeImmutable $now = null): string
    {
        return ($now ?? new \DateTimeImmutable('now'))->setTimezone(new \DateTimeZone('Europe/London'))->format('Y-m-d');
    }

    /** Whole calendar days from today (UK) to $date; negative when it's in the past. */
    public static function daysUntil(string $date, ?\DateTimeImmutable $now = null): int
    {
        $utc = new \DateTimeZone('UTC');
        $today = new \DateTimeImmutable(self::todayUk($now), $utc);
        $target = new \DateTimeImmutable($date, $utc);
        $diff = $today->diff($target);
        return $diff->invert ? -(int)$diff->days : (int)$diff->days;
    }
}
