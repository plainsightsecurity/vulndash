<?php
/**
 * Analog risk-score gauge (semicircular dial). Expects $risk in scope - the
 * array from VulnerabilityRepository::getRiskScore(). Renders a 0-100 needle
 * dial whose arc is split into the four vulnerability-severity colour zones
 * (--sev-low -> --sev-critical), so the gauge reads in the same palette as the
 * severity cards and the needle lands in a zone whose colour and name match the
 * risk band.
 *
 * The arc is drawn as four stroked polylines whose points are computed here in
 * PHP (not SVG arc commands), so curvature is deterministic and theme colours
 * come from CSS variables via the .sev-* classes - see .risk-gauge in
 * public/assets/css/style.css. No JavaScript: the needle angle is baked into
 * the markup from the score.
 *
 * @var array{score:int,band:string,band_class:string,risk_points:float,findings:int,kev_findings:int,assets:int,density:float} $risk
 */

use VulnDash\Lib\Helpers;

// --- geometry ---------------------------------------------------------------
$cx = 150.0; $cy = 150.0; $r = 120.0;      // centre + arc radius (viewBox 0 0 300 190)
$score = max(0, min(100, (int)$risk['score']));

// Point on the dial for a fraction t in [0,1]: t=0 is the LOW (left) end, t=1
// the HIGH (right) end, sweeping over the top. ang = 180deg + 180deg*t.
$pt = static function (float $t, float $radius) use ($cx, $cy): array {
    $ang = M_PI * (1.0 + $t);               // t=0 -> pi (left), t=1 -> 2pi (right)
    return [$cx + $radius * cos($ang), $cy + $radius * sin($ang)];
};

// Four equal severity zones, drawn as thick round-capped polylines. A tiny gap
// between zones keeps the colour boundaries crisp.
$zones = [
    ['sev-low',      0.00, 0.25],
    ['sev-medium',   0.25, 0.50],
    ['sev-high',     0.50, 0.75],
    ['sev-critical', 0.75, 1.00],
];
$zonePolylines = [];
foreach ($zones as [$cls, $t0, $t1]) {
    $gap = 0.008;                            // small inset so segments don't merge
    $a = $t0 + ($t0 > 0 ? $gap : 0.0);
    $b = $t1 - ($t1 < 1 ? $gap : 0.0);
    $steps = 14;
    $pts = [];
    for ($i = 0; $i <= $steps; $i++) {
        $t = $a + ($b - $a) * ($i / $steps);
        [$x, $y] = $pt($t, $r);
        $pts[] = round($x, 2) . ',' . round($y, 2);
    }
    $zonePolylines[] = [$cls, implode(' ', $pts)];
}

// Needle: a slim triangle from the hub to the score position.
$t = $score / 100.0;
$ang = M_PI * (1.0 + $t);
$dirx = cos($ang); $diry = sin($ang);
$perpx = -$diry;   $perpy = $dirx;
[$tipx, $tipy] = $pt($t, $r * 0.70);
$half = 6.0;
$b1x = $cx + $perpx * $half; $b1y = $cy + $perpy * $half;
$b2x = $cx - $perpx * $half; $b2y = $cy - $perpy * $half;
$needle = round($tipx, 2) . ',' . round($tipy, 2) . ' '
        . round($b1x, 2) . ',' . round($b1y, 2) . ' '
        . round($b2x, 2) . ',' . round($b2y, 2);

// LOW / HIGH captions sit in the empty band BELOW the arc ends, so they never
// overlay the coloured stroke. Centred under each end of the dial.
$capY = 178.0;
$lowx = $cx - $r;   // under the left (LOW) end
$highx = $cx + $r;  // under the right (HIGH) end

$ariaLabel = "Risk score {$score} out of 100, {$risk['band']}";
?>
<div class="panel risk-panel">
    <div class="risk-gauge-wrap">
        <svg class="risk-gauge" viewBox="0 0 300 190" role="img" aria-label="<?= Helpers::e($ariaLabel) ?>">
            <!-- track (subtle backing arc) -->
            <?php [$tx0,$ty0]=$pt(0.0,$r); ?>
            <polyline class="risk-gauge-track"
                points="<?php
                    $tp=[]; for($i=0;$i<=56;$i++){ [$x,$y]=$pt($i/56,$r); $tp[]=round($x,2).','.round($y,2);} echo implode(' ',$tp);
                ?>" />
            <!-- coloured severity zones -->
            <?php foreach ($zonePolylines as [$cls, $points]): ?>
            <polyline class="risk-gauge-zone <?= Helpers::e($cls) ?>" points="<?= Helpers::e($points) ?>" />
            <?php endforeach; ?>
            <!-- end labels -->
            <text class="risk-gauge-end" x="<?= round($lowx,1) ?>" y="<?= round($capY,1) ?>" text-anchor="middle">LOW</text>
            <text class="risk-gauge-end" x="<?= round($highx,1) ?>" y="<?= round($capY,1) ?>" text-anchor="middle">HIGH</text>
            <!-- needle + hub -->
            <polygon class="risk-gauge-needle <?= Helpers::e($risk['band_class']) ?>" points="<?= Helpers::e($needle) ?>" />
            <circle class="risk-gauge-hub" cx="<?= $cx ?>" cy="<?= $cy ?>" r="9" />
            <!-- score readout -->
            <text class="risk-gauge-score <?= Helpers::e($risk['band_class']) ?>" x="<?= $cx ?>" y="108" text-anchor="middle"><?= $score ?></text>
            <text class="risk-gauge-band" x="<?= $cx ?>" y="130" text-anchor="middle"><?= Helpers::e(strtoupper($risk['band'])) ?> RISK</text>
        </svg>
    </div>

    <div class="risk-meta">
        <h2 class="risk-meta-title">Risk score</h2>
        <?php if ((int)$risk['assets'] === 0): ?>
        <p class="risk-meta-note">No assets in this scope yet, so there's nothing to score.</p>
        <?php else: ?>
        <p class="risk-meta-note">
            A single 0&ndash;100 measure of this view's current exposure, weighted by
            severity and by whether findings are known to be exploited. Higher is worse.
        </p>
        <dl class="risk-meta-stats">
            <div><dt>Open findings</dt><dd><?= number_format($risk['findings']) ?></dd></div>
            <div><dt>Known exploited</dt><dd><?= number_format($risk['kev_findings']) ?></dd></div>
            <div><dt>Assets in scope</dt><dd><?= number_format($risk['assets']) ?></dd></div>
        </dl>
        <?php endif; ?>
    </div>
</div>
