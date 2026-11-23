<?php
declare(strict_types=1);

// Runs every tests/cases/*Test.php (or just the files named on the command
// line). Called by tests/run.sh, which sets VULNDASH_CONFIG and builds the
// vulndash_test database first.

require __DIR__ . '/lib.php';

$files = array_slice($argv, 1) ?: glob(__DIR__ . '/cases/*Test.php');
sort($files);
foreach ($files as $file) {
    $GLOBALS['__current_file'] = $file;
    require $file;
}

$cfgRef = new ReflectionProperty(VulnDash\Lib\Config::class, 'data');
VulnDash\Lib\Config::get('app.name');
$pristineConfig = $cfgRef->getValue();

$pass = 0;
$failed = [];
$lastFile = '';
foreach ($GLOBALS['__tests'] as $t) {
    if ($t['file'] !== $lastFile) {
        echo "\n{$t['file']}\n";
        $lastFile = $t['file'];
    }
    $cfgRef->setValue(null, $pristineConfig);
    $_SESSION = [];
    try {
        reset_db();
        ($t['fn'])();
        echo "  ok    {$t['name']}\n";
        $pass++;
    } catch (Throwable $e) {
        $why = $e instanceof TestFailure ? $e->getMessage()
            : get_class($e) . ': ' . $e->getMessage() . ' (' . basename($e->getFile()) . ':' . $e->getLine() . ')';
        echo "  FAIL  {$t['name']}\n        $why\n";
        $failed[] = "{$t['file']}: {$t['name']}";
    }
}

echo "\n" . $pass . ' passed, ' . count($failed) . " failed\n";
foreach ($failed as $f) {
    echo "  - $f\n";
}
exit($failed === [] ? 0 : 1);
