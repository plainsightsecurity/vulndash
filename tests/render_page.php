<?php
declare(strict_types=1);

// Renders one public page in-process, the way Apache would, for
// tests/pages.php. Usage: php tests/render_page.php <page.php> <query> <role>
// role: admin | client | anon. Any PHP warning/notice/deprecation is printed
// as a "PHPERR:" line so the caller can fail on it.

[$_, $page, $query, $role] = $argv + [null, '', '', 'anon'];

error_reporting(E_ALL);
ini_set('display_errors', '0');
set_error_handler(static function (int $no, string $msg, string $file, int $line): bool {
    if (error_reporting() & $no) {
        fwrite(STDOUT, "\nPHPERR: $msg in " . basename($file) . ":$line\n");
    }
    return true;
});
register_shutdown_function(static function (): void {
    $e = error_get_last();
    if ($e !== null && in_array($e['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR], true)) {
        fwrite(STDOUT, "\nPHPERR: FATAL {$e['message']} in " . basename($e['file']) . ":{$e['line']}\n");
    }
});

$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['REQUEST_URI'] = '/' . preg_replace('/\.php$/', '', $page) . ($query !== '' ? "?$query" : '');
$_SERVER['HTTP_HOST'] = 'dashboard.test';
$_SERVER['REMOTE_ADDR'] = '127.0.0.1';
parse_str($query, $_GET);

require __DIR__ . '/../src/bootstrap.php';

$_SESSION = ['csrf_token' => str_repeat('a', 64)];
if ($role === 'admin') {
    $_SESSION += ['user_id' => 1, 'username' => 'admin', 'is_admin' => true, 'tag_ids' => [], 'last_activity' => time()];
} elseif ($role === 'client') {
    $_SESSION += ['user_id' => 2, 'username' => 'client', 'is_admin' => false, 'tag_ids' => [1], 'last_activity' => time()];
}

chdir(dirname(__DIR__ . '/../public/' . $page));
require __DIR__ . '/../public/' . $page;
