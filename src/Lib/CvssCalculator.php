<?php
declare(strict_types=1);

namespace VulnDash\Lib;

/**
 * Works out the "effective" CVSS base score for a vulnerability, and whether
 * it counts as a Cyber Essentials Plus failure (CVSS >= 7.0).
 *
 * Precedence, as specified:
 *   1. CVSS3(.1) base score, if the KnowledgeBase entry has one
 *   2. CVSS2 base score, if it has one and no CVSS3 score
 *   3. An estimate derived from the Qualys severity level (1-5), if neither
 *      CVSS score is published for that QID
 *
 * The severity-level estimate uses the midpoint of the relevant band. Only
 * High (7.0-8.9) and Critical (9.0-10.0) were specified in the business
 * requirement, since only those bands can ever cross the CE+ threshold of
 * 7.0. Informational/Low/Medium midpoints below are this codebase's own
 * extension - added so every vulnerability still gets a displayable score
 * elsewhere in the dashboard - and use the standard NVD CVSS v3 qualitative
 * bands (None 0.0, Low 0.1-3.9, Medium 4.0-6.9). Adjust
 * SEVERITY_ESTIMATE_MIDPOINTS below if you'd rather they worked differently;
 * it's the only place this logic lives.
 *
 * ZERO-DAY CARVE-OUT (added 2026-08-21). Qualys sometimes ships a QID for a
 * vulnerability with no vendor fix yet and marks the title accordingly, e.g.
 * "... Vulnerability (Zero Day)", "... - Zero Day", "... (ZeroDay)". A
 * finding like that can carry a high/critical CVSS score, but there is
 * nothing yet for the client to remediate - CE+ failing is meant to drive
 * "go apply this fix", and there is no fix to apply - so it must not count
 * as a CE+ failure. Qualys renames the QID (dropping the "Zero Day" wording)
 * once a fix ships; the next detection sync re-evaluates the (now-changed)
 * title and the QID becomes a normal CE+-eligible finding again on its own -
 * nothing else has to change. isZeroDayTitle() is deliberately the only
 * place that pattern is matched, for the same "one choke point" reason the
 * docblock above gives for SEVERITY_ESTIMATE_MIDPOINTS.
 */
class CvssCalculator
{
    public const CE_PLUS_THRESHOLD = 7.0;

    /** @var array<int, float> Qualys severity level => estimated midpoint CVSS score */
    private const SEVERITY_ESTIMATE_MIDPOINTS = [
        1 => 0.0,   // Informational - this codebase's assumption, not in the original spec
        2 => 2.0,   // Low           - this codebase's assumption, not in the original spec
        3 => 5.45,  // Medium        - this codebase's assumption, not in the original spec
        4 => 7.95,  // High: midpoint of 7.0-8.9, as specified
        5 => 9.5,   // Critical: midpoint of 9.0-10.0, as specified
    ];

    /**
     * Matches "Zero Day", "Zero-Day" and "ZeroDay" (any casing, with or
     * without a separating space/hyphen) anywhere in a KB title - e.g. the
     * "(Zero Day)", "(ZeroDay)" and "- Zero Day" suffixes Qualys uses. Not
     * anchored to the end of the string on purpose: Qualys hasn't been
     * perfectly consistent about where in the title the marker sits.
     */
    private const ZERO_DAY_PATTERN = '/\bzero[\s-]?day\b/i';

    /**
     * @return array{score: float, source: string, is_ce_plus_fail: bool, is_zero_day: bool}
     */
    public static function calculate(?float $cvss3Base, ?float $cvss2Base, int $qualysSeverity, ?string $title = null): array
    {
        if ($cvss3Base !== null && $cvss3Base > 0.0) {
            $score  = $cvss3Base;
            $source = 'CVSS3';
        } elseif ($cvss2Base !== null && $cvss2Base > 0.0) {
            $score  = $cvss2Base;
            $source = 'CVSS2';
        } else {
            $score  = self::SEVERITY_ESTIMATE_MIDPOINTS[$qualysSeverity] ?? 0.0;
            $source = 'QUALYS_SEVERITY_ESTIMATE';
        }

        // $title is optional (nullable) purely so existing/future callers
        // that genuinely don't have a title on hand still get a score back
        // rather than a hard error - every current caller has one and should
        // pass it, since omitting it silently disables the carve-out above.
        $isZeroDay = $title !== null && self::isZeroDayTitle($title);

        return [
            'score'           => $score,
            'source'          => $source,
            'is_ce_plus_fail' => !$isZeroDay && $score >= self::CE_PLUS_THRESHOLD,
            'is_zero_day'     => $isZeroDay,
        ];
    }

    /**
     * True if $title carries Qualys's zero-day marker. Public and standalone
     * (rather than folded silently into calculate()) so views can explain an
     * unexpected "CE+ Pass" on a high/critical finding without re-deriving
     * CE+ status themselves - see vulnerability_detail.php's "Zero-day" badge.
     */
    public static function isZeroDayTitle(string $title): bool
    {
        return preg_match(self::ZERO_DAY_PATTERN, $title) === 1;
    }
}
