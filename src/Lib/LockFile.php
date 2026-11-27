<?php
declare(strict_types=1);

namespace VulnDash\Lib;

/**
 * Opens a script's single-instance lock file in /tmp (2026-11-27).
 *
 * Ubuntu's fs.protected_regular (on by default) stops anyone - root included
 * - from opening, with "create if missing", a file in a sticky world-writable
 * directory like /tmp that another user owns. So a lock file left behind by a
 * different user (root, before scripts refused to run as root; or www-data,
 * when root later runs migrate.php --root) made fopen($path, 'c') fail and
 * the script stop with "Could not open lock file". Opening an EXISTING file
 * read-only isn't affected, and flock() works on a read-only handle, so that
 * is tried first; 'c' is only used to create the file when it isn't there.
 *
 * @return resource|false as fopen()
 */
final class LockFile
{
    public static function open(string $path)
    {
        if (is_file($path)) {
            $h = @fopen($path, 'r');
            if ($h !== false) {
                return $h;
            }
        }
        $h = @fopen($path, 'c');
        if ($h !== false) {
            @chmod($path, 0666);
        }
        return $h;
    }
}
