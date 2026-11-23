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
            self::$data = require __DIR__ . '/../config/config.php';
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
