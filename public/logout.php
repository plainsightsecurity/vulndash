<?php
declare(strict_types=1);

require_once __DIR__ . '/../src/bootstrap.php';

use VulnDash\Lib\Auth;

Auth::logout();
header('Location: /login');
exit;
