<?php
declare(strict_types=1);

namespace VulnDash\Lib;

/**
 * When an asset's Cloud Agent counts as "not reporting" - the one home of
 * the rule, so the Assets list, detail page, dashboard card and PDF cover
 * can't disagree.
 *
 * WHY. On this agent-only platform a host whose agent stops reporting
 * (uninstalled, machine rebuilt, broken check-in, laptop in a drawer) keeps
 * whatever findings it had when it last reported. Nothing marks them stale,
 * so the host can look clean, or comfortably inside the CE+ patch window
 * (CePlusDeadline), purely because nothing new is arriving - the dangerous
 * direction for a compliance view. Flagging the host is how the dashboard
 * says "these findings may be out of date".
 *
 * RULE. Stale once assets.last_scan_date (Qualys's LAST_VM_SCANNED_DATE,
 * stored UTC, refreshed for every host by the hourly reconcile) is older than
 * assets.stale_after_days in src/config/config.php - default 7: long enough
 * to ignore a laptop off over a weekend or a short holiday, short enough to
 * catch a dead agent well inside a 14-day CE+ window.
 *
 * A NULL last_scan_date counts as stale too ("never reported"), deliberately:
 * an asset with no evidence of ever reporting is exactly what this exists to
 * surface, and fail-loud is the safer error. Worth knowing: the plain Host
 * List endpoint's last-scan field name is still a best guess (see
 * QualysApiClient::parseHostListFile()), so zero-detection hosts written via
 * that path could carry NULL here. If many show as "never reported" after
 * deploying, that guess is the first thing to check.
 */
final class StaleAgent
{
    public const DEFAULT_STALE_AFTER_DAYS = 7;

    /** The configured threshold; anything that isn't a positive whole number falls back to the default. */
    public static function staleAfterDays(): int
    {
        $setting = Config::get('assets.stale_after_days');
        if ($setting !== null && filter_var($setting, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]) !== false) {
            return (int)$setting;
        }
        return self::DEFAULT_STALE_AFTER_DAYS;
    }

    /**
     * The UTC instant an asset must have last reported before to be stale now -
     * bound into SQL by VulnerabilityRepository's stale filter as
     * "last_scan_date IS NULL OR last_scan_date < :cutoff", the same
     * comparison status() makes below.
     */
    public static function cutoffUtc(?\DateTimeImmutable $now = null): string
    {
        $now = ($now ?? new \DateTimeImmutable('now'))->setTimezone(new \DateTimeZone('UTC'));
        return $now->modify('-' . self::staleAfterDays() . ' days')->format('Y-m-d H:i:s');
    }

    /**
     * Null when the agent is reporting normally; otherwise how stale it is.
     * 'days' is whole calendar days (UK time) since the last report - same
     * convention as CePlusDeadline, so it matches the date shown - and null
     * when the asset has never reported.
     *
     * @return array{days: ?int}|null
     */
    public static function status(?string $lastScanUtc, ?\DateTimeImmutable $now = null): ?array
    {
        if ($lastScanUtc === null || $lastScanUtc === '') {
            return ['days' => null];
        }

        try {
            $last = new \DateTimeImmutable($lastScanUtc, new \DateTimeZone('UTC'));
        } catch (\Exception $e) {
            return ['days' => null];
        }

        $now = $now ?? new \DateTimeImmutable('now');
        if ($last->format('Y-m-d H:i:s') >= self::cutoffUtc($now)) {
            return null;
        }

        $london = new \DateTimeZone('Europe/London');
        $utc = new \DateTimeZone('UTC');
        $days = (new \DateTimeImmutable($now->setTimezone($london)->format('Y-m-d'), $utc))
            ->diff(new \DateTimeImmutable($last->setTimezone($london)->format('Y-m-d'), $utc))
            ->days;

        return ['days' => (int)$days];
    }

    /** "Not reporting · 12 days" / "Not reporting · never reported". */
    public static function label(array $status): string
    {
        if ($status['days'] === null) {
            return 'Not reporting · never reported';
        }
        return 'Not reporting · ' . $status['days'] . ' day' . ($status['days'] === 1 ? '' : 's');
    }

    /**
     * "12 days ago" / "Never reported" - the compact form for the Assets
     * list, where the chip stands in for the date in the Last scan column
     * (the long label() wrapped into a two-line pill there). Callers put
     * label()'s full wording, and the real date, in the chip's title so
     * nothing is lost on hover.
     */
    public static function shortLabel(array $status): string
    {
        if ($status['days'] === null) {
            return 'Never reported';
        }
        return $status['days'] . ' day' . ($status['days'] === 1 ? '' : 's') . ' ago';
    }
}
