#!/usr/bin/env php
<?php
declare(strict_types=1);

/**
 * Creates a user account and assigns it to one or more Qualys tags.
 *
 * A CLI tool rather than a web admin page, deliberately: account creation is
 * an infrequent, high-trust operation, so keeping it off the web surface
 * entirely is a reasonable trade for this v1. If you'd rather have a proper
 * admin UI for this, it's a natural next addition - just say the word.
 *
 * Usage:
 *   php scripts/create_account.php --username=jsmith --email=jsmith@client.com --tags=1001,2002
 *   php scripts/create_account.php --username=admin2 --email=admin2@plainsightsecurity.co.uk --admin
 *
 * You'll be prompted to type the password interactively - it's deliberately
 * not accepted as a CLI argument so it never ends up in shell history.
 * --tags takes Qualys tag identifiers (the qualys_tag_id column) - a
 * numeric tag ID, a tag name, or an Activation ID (UUID), whichever your
 * Qualys data uses - not local tag table IDs. The tag must already exist
 * locally (i.e. added via the admin UI or a tag sync must have run) or it
 * will be skipped with a warning.
 */

require_once __DIR__ . '/../src/bootstrap.php';

use VulnDash\Lib\Database;

function usageAndExit(): void
{
    fwrite(STDERR, "Usage: php scripts/create_account.php --username=<name> --email=<email> [--tags=<comma-separated Qualys tag identifiers>] [--admin]\n");
    exit(1);
}

$options = getopt('', ['username:', 'email:', 'tags::', 'admin']);

if (empty($options['username']) || empty($options['email'])) {
    usageAndExit();
}

$username = (string)$options['username'];
$email    = (string)$options['email'];
$isAdmin  = array_key_exists('admin', $options);
$tagIds   = [];

if (!empty($options['tags'])) {
    $tagIds = array_filter(array_map('trim', explode(',', (string)$options['tags'])));
}

if (!$isAdmin && empty($tagIds)) {
    fwrite(STDERR, "Warning: no --tags supplied and --admin not set. This account will see no data until tags are assigned.\n");
}

fwrite(STDOUT, "Enter password for {$username}: ");
shell_exec('stty -echo');
$password = trim((string)fgets(STDIN));
shell_exec('stty echo');
fwrite(STDOUT, "\n");

if (strlen($password) < 12) {
    fwrite(STDERR, "Password must be at least 12 characters.\n");
    exit(1);
}

$pdo = Database::getConnection();
$pdo->beginTransaction();

try {
    $stmt = $pdo->prepare(
        'INSERT INTO users (username, email, password_hash, is_admin) VALUES (:username, :email, :hash, :is_admin)'
    );
    $stmt->execute([
        'username' => $username,
        'email'    => $email,
        'hash'     => password_hash($password, PASSWORD_BCRYPT),
        'is_admin' => $isAdmin ? 1 : 0,
    ]);
    $userId = (int)$pdo->lastInsertId();

    foreach ($tagIds as $qualysTagId) {
        $tagStmt = $pdo->prepare('SELECT id FROM tags WHERE qualys_tag_id = :qtag');
        $tagStmt->execute(['qtag' => $qualysTagId]);
        $tag = $tagStmt->fetch();

        if (!$tag) {
            fwrite(STDERR, "Warning: no local tag found for Qualys identifier {$qualysTagId} - skipped. Has it been added yet (admin UI or tag sync)?\n");
            continue;
        }

        $pdo->prepare('INSERT IGNORE INTO user_tags (user_id, tag_id) VALUES (:user_id, :tag_id)')
            ->execute(['user_id' => $userId, 'tag_id' => $tag['id']]);
    }

    $pdo->commit();
    fwrite(STDOUT, "Account '{$username}' created (id {$userId}).\n");
} catch (\Throwable $e) {
    $pdo->rollBack();
    fwrite(STDERR, 'Failed to create account: ' . $e->getMessage() . "\n");
    exit(1);
}
