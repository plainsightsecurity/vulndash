<?php
declare(strict_types=1);

namespace VulnDash\Lib;

/**
 * A single shared PDO connection per request/process, configured for strict
 * error handling and real prepared statements (not client-side emulation) so
 * every ? / :param placeholder is genuinely escaped by the database driver.
 */
class Database
{
    private static ?\PDO $instance = null;

    public static function getConnection(): \PDO
    {
        if (self::$instance === null) {
            $dsn = sprintf(
                'mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4',
                Config::get('db.host'),
                Config::get('db.port'),
                Config::get('db.name')
            );

            self::$instance = new \PDO(
                $dsn,
                Config::get('db.user'),
                Config::get('db.password'),
                [
                    \PDO::ATTR_ERRMODE            => \PDO::ERRMODE_EXCEPTION,
                    \PDO::ATTR_DEFAULT_FETCH_MODE  => \PDO::FETCH_ASSOC,
                    \PDO::ATTR_EMULATE_PREPARES    => false,
                ]
            );

            // Pin this session to the same named zone as PHP's own
            // date_default_timezone_set('Europe/London') in bootstrap.php,
            // rather than trusting time_zone=SYSTEM - confirmed 2026-07
            // that SYSTEM was silently stale (still resolving to UTC) on
            // this box. A named zone (rather than a fixed '+00:00'/'+01:00'
            // offset) is what makes NOW()/CURRENT_TIMESTAMP correctly
            // switch between GMT and BST on the actual DST boundary dates
            // instead of needing a manual offset flip twice a year.
            //
            // This requires MariaDB's time zone tables to be loaded, which
            // is a one-time step this app doesn't run itself:
            //     mysql_tzinfo_to_sql /usr/share/zoneinfo | sudo mysql -u root mysql
            // Verify with: SELECT COUNT(*) FROM mysql.time_zone_name;
            // (should be in the thousands, not 0). Fails loudly here with
            // a specific, actionable message rather than a bare PDO error
            // if that step was skipped.
            try {
                self::$instance->exec("SET time_zone = 'Europe/London'");
            } catch (\PDOException $e) {
                throw new \RuntimeException(
                    "MariaDB rejected time zone 'Europe/London' - the server's time zone "
                    . "tables are almost certainly not loaded yet. Run this once, as root: "
                    . "mysql_tzinfo_to_sql /usr/share/zoneinfo | sudo mysql -u root mysql",
                    0,
                    $e
                );
            }
        }

        return self::$instance;
    }
}
