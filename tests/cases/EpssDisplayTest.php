<?php
declare(strict_types=1);

// EPSS display: nearest whole percent, "<1%" below that, never above 100%.

use VulnDash\Lib\Helpers;

test('EPSS shown as a whole-number percentage', function () {
    eq(Helpers::epssPercent(0.0), '<1%', 'zero is still scored');
    eq(Helpers::epssPercent(0.00043), '<1%');
    eq(Helpers::epssPercent(0.0099), '<1%', 'just under 1% is not rounded up');
    eq(Helpers::epssPercent(0.01), '1%');
    eq(Helpers::epssPercent(0.0934), '9%');
    eq(Helpers::epssPercent(0.0995), '10%', 'nearest, not ceil');
    eq(Helpers::epssPercent(1.0), '100%');
});

test('EPSS tooltip gives the exact percentage', function () {
    eq(Helpers::epssTooltip(0.0972), '9.72% chance of exploitation in the next 30 days (FIRST EPSS)');
    eq(Helpers::epssTooltip(0.00043), '0.04% chance of exploitation in the next 30 days (FIRST EPSS)');
    eq(Helpers::epssTooltip(0.00002), '<0.01% chance of exploitation in the next 30 days (FIRST EPSS)', 'tiny but scored');
    eq(Helpers::epssTooltip(0.0), '0.00% chance of exploitation in the next 30 days (FIRST EPSS)');
    eq(Helpers::epssTooltip(1.0), '100.00% chance of exploitation in the next 30 days (FIRST EPSS)');
});
