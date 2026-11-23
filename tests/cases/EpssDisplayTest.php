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
