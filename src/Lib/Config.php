<?php
declare(strict_types=1);

namespace VulnDash\Lib;

/**
 * Tiny wrapper around src/config/config.php so the rest of the app can do
 * Config::get('qualys.api_base_url') instead of juggling nested arrays.
 */
class Config
{
    private static ?array $data = null;

    public static function get(string $key)
    {
        if (self::$data === null) {
            // VULNDASH_CONFIG lets the test suite (tests/run.sh) point at
            // tests/config.test.php so running tests can never read or
            // overwrite the live src/config/config.php. Nothing on the
            // server sets it, and Apache doesn't pass arbitrary environment
            // variables through to PHP, so production always takes the default.
            $path = getenv('VULNDASH_CONFIG') ?: __DIR__ . '/../config/config.php';
            self::$data = require $path;
        }

        $value = self::$data;
        foreach (explode('.', $key) as $part) {
            if (!is_array($value) || !array_key_exists($part, $value)) {
                return null;
            }
            $value = $value[$part];
        }

        return $value;
    }
}
