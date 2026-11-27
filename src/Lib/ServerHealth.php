<?php
declare(strict_types=1);

namespace VulnDash\Lib;

/**
 * Disk space and database size (2026-11-27), for the API Usage page's Server
 * panel, the dashboard's status panel and the admin disk alerts
 * (ServerHealthAlerts). A full disk stops MySQL, the cron logs and the
 * nightly backups all at once, and nothing else here would notice.
 *
 * Disks: the filesystems holding the places this app depends on - the root
 * filesystem, MySQL's data directory (@@datadir), the app itself, its logs
 * and the backup staging area - each listed once however many of those it
 * holds (grouped by device). Works as www-data: statvfs() and stat() need
 * no read access to MySQL's own directory. Extra paths can be added with
 * alerts.disk_paths.
 *
 * Database: total and largest tables, with information_schema's size cache
 * switched off for this one query (MySQL 8 otherwise reports sizes up to a
 * day old - information_schema_stats_expiry).
 */
final class ServerHealth
{
    public const DEFAULT_WARN_PERCENT = 85;

    /** Back below this many points under the warning level counts as fixed, so a disk hovering at the line doesn't flap. */
    public const RECOVERY_MARGIN = 5;

    public static function warnPercent(): int
    {
        return min(99, max(50, (int)(Config::get('alerts.disk_warn_percent') ?? self::DEFAULT_WARN_PERCENT)));
    }

    /**
     * @return array<int, array{mount: string, holds: string[], total: float, free: float, used_pct: float}>
     *         one per filesystem, fullest first
     */
    public static function filesystems(): array
    {
        $candidates = [
            '/'                   => 'system',
            self::mysqlDatadir()  => 'MySQL data',
            dirname(__DIR__, 2)   => 'the app',
            '/var/log/vulndash'   => 'cron logs',
            '/var/backups'        => 'backups',
        ];
        foreach ((array)(Config::get('alerts.disk_paths') ?? []) as $extra) {
            $candidates[(string)$extra] = (string)$extra;
        }

        $byDevice = [];
        foreach ($candidates as $path => $what) {
            if ($path === '' || !file_exists($path)) {
                continue;
            }
            $st = @stat($path);
            $total = @disk_total_space($path);
            $free = @disk_free_space($path);
            if ($st === false || $total === false || $free === false || $total <= 0) {
                continue;
            }
            $dev = (string)$st['dev'];
            if (!isset($byDevice[$dev])) {
                $byDevice[$dev] = [
                    'mount'    => self::mountPointOf($path),
                    'holds'    => [],
                    'total'    => (float)$total,
                    'free'     => (float)$free,
                    'used_pct' => round(100 * (1 - $free / $total), 1),
                ];
            }
            $byDevice[$dev]['holds'][] = $what;
        }
        $list = array_values($byDevice);
        usort($list, static fn (array $a, array $b): int => $b['used_pct'] <=> $a['used_pct']);
        return $list;
    }

    /**
     * @return array{total: float, tables: array<int, array{name: string, bytes: float, rows: int}>}
     *         tables: the $top largest
     */
    public static function databaseSize(int $top = 8): array
    {
        $pdo = Database::getConnection();
        try {
            $pdo->exec('SET SESSION information_schema_stats_expiry = 0');
        } catch (\PDOException) {
            // Older server or no permission: cached figures are still useful.
        }
        $rows = $pdo->query("
            SELECT table_name AS name, COALESCE(data_length, 0) + COALESCE(index_length, 0) AS bytes, COALESCE(table_rows, 0) AS est_rows
            FROM information_schema.tables
            WHERE table_schema = DATABASE() AND table_type = 'BASE TABLE'
            ORDER BY bytes DESC
        ")->fetchAll();
        $total = 0.0;
        foreach ($rows as $r) {
            $total += (float)$r['bytes'];
        }
        return [
            'total'  => $total,
            'tables' => array_map(static fn (array $r): array => ['name' => (string)$r['name'], 'bytes' => (float)$r['bytes'], 'rows' => (int)$r['est_rows']],
                array_slice($rows, 0, $top)),
        ];
    }

    /** e.g. "3.1 GB". */
    public static function bytes(float $b): string
    {
        foreach (['TB' => 1024 ** 4, 'GB' => 1024 ** 3, 'MB' => 1024 ** 2, 'KB' => 1024] as $unit => $size) {
            if ($b >= $size) {
                return number_format($b / $size, $b / $size >= 100 ? 0 : 1) . ' ' . $unit;
            }
        }
        return number_format($b) . ' B';
    }

    private static function mysqlDatadir(): string
    {
        try {
            $d = Database::getConnection()->query('SELECT @@datadir')->fetchColumn();
            return is_string($d) ? rtrim($d, '/') : '';
        } catch (\Throwable) {
            return '';
        }
    }

    /** The mount point a path lives on, from /proc/mounts (longest matching prefix). */
    private static function mountPointOf(string $path): string
    {
        $real = realpath($path) ?: $path;
        $best = '/';
        foreach (@file('/proc/mounts', FILE_IGNORE_NEW_LINES) ?: [] as $line) {
            $mp = str_replace('\040', ' ', (string)(explode(' ', $line)[1] ?? ''));
            if ($mp !== '' && ($real === $mp || str_starts_with($real, rtrim($mp, '/') . '/')) && strlen($mp) > strlen($best)) {
                $best = $mp;
            }
        }
        return $best;
    }
}
