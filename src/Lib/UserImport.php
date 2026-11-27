<?php
declare(strict_types=1);

namespace VulnDash\Lib;

/**
 * Bulk account creation from CSV (admin Manage Users, 2026-11).
 *
 * Header row required; columns in any order, case-insensitive:
 *
 *   username      required
 *   email         required, checked by Helpers::emailError()
 *   organisation  optional, an existing organisation's name
 *   tags          optional, extra tag names separated by ";"
 *   org_admin     optional, yes/no (true/false, 1/0) - needs an organisation
 *
 * All or nothing: every row is checked first (missing fields, bad emails,
 * unknown organisations or tags, usernames/emails already taken or repeated
 * in the file, an account that would see no data) and if any row has a
 * problem nothing is created. Imported accounts are clients - never admins,
 * no uninstall grant. Organisation user limits are reported, not enforced:
 * they bind organisation admins, and the person importing is a Plainsight Security
 * admin, who can already go past them.
 */
final class UserImport
{
    public const MAX_ROWS  = 500;
    public const MAX_BYTES = 1048576;

    /**
     * @return array{rows: array<int, array{line: int, username: string, email: string, organisation_id: ?int,
     *               organisation: ?string, tag_ids: int[], tags: string[], org_admin: bool}>,
     *               errors: string[], warnings: string[]}
     */
    public static function parse(string $csv): array
    {
        $errors = [];
        if (strlen($csv) > self::MAX_BYTES) {
            return ['rows' => [], 'errors' => ['The file is larger than 1 MB.'], 'warnings' => []];
        }
        $csv = preg_replace('/^\xEF\xBB\xBF/', '', $csv); // Excel's UTF-8 BOM
        $lines = preg_split('/\r\n|\n|\r/', trim((string)$csv));
        if ($lines === false || $lines === [''] || $lines === []) {
            return ['rows' => [], 'errors' => ['The file is empty.'], 'warnings' => []];
        }

        $header = array_map(static fn ($h) => strtolower(trim((string)$h)), str_getcsv(array_shift($lines)));
        $known = ['username', 'email', 'organisation', 'tags', 'org_admin'];
        foreach (['username', 'email'] as $required) {
            if (!in_array($required, $header, true)) {
                $errors[] = "The header row needs a \"{$required}\" column (columns: " . implode(', ', $known) . ').';
            }
        }
        if ($unknown = array_diff(array_filter($header), $known)) {
            $errors[] = 'Unknown column(s): ' . implode(', ', $unknown) . '. Allowed: ' . implode(', ', $known) . '.';
        }
        if ($errors !== []) {
            return ['rows' => [], 'errors' => $errors, 'warnings' => []];
        }
        $lines = array_values(array_filter($lines, static fn ($l) => trim($l, " \t,") !== ''));
        if (count($lines) > self::MAX_ROWS) {
            return ['rows' => [], 'errors' => ['At most ' . self::MAX_ROWS . ' accounts per import (this file has ' . count($lines) . ').'], 'warnings' => []];
        }
        if ($lines === []) {
            return ['rows' => [], 'errors' => ['There are no accounts in the file, only a header row.'], 'warnings' => []];
        }

        $orgsByName = [];
        foreach (OrganisationRepository::listAll() as $org) {
            $orgsByName[mb_strtolower($org['name'])] = $org;
        }
        $tagsByName = [];
        foreach (UserRepository::listTags() as $tag) {
            $tagsByName[mb_strtolower((string)$tag['name'])] = (int)$tag['id'];
        }
        $pdo = Database::getConnection();
        $taken = $pdo->prepare('SELECT username, email FROM users WHERE username = :u OR email = :e LIMIT 1');

        $rows = [];
        $seenUsernames = $seenEmails = [];
        $addingPerOrg = [];
        foreach ($lines as $i => $line) {
            $lineNo = $i + 2; // header is line 1
            $cells = str_getcsv($line);
            $get = static function (string $col) use ($header, $cells): string {
                $idx = array_search($col, $header, true);
                return $idx === false ? '' : trim((string)($cells[$idx] ?? ''));
            };
            $username = $get('username');
            $email = $get('email');
            $orgName = $get('organisation');
            $tagNames = array_values(array_filter(array_map('trim', explode(';', $get('tags'))), static fn ($t) => $t !== ''));
            $orgAdminRaw = strtolower($get('org_admin'));
            $problems = [];

            if ($username === '' || mb_strlen($username) > 64) {
                $problems[] = 'username is missing or longer than 64 characters';
            }
            if (($emailError = Helpers::emailError($email)) !== null) {
                $problems[] = rtrim(lcfirst($emailError), '.');
            }
            $uKey = mb_strtolower($username);
            $eKey = mb_strtolower($email);
            if ($username !== '' && isset($seenUsernames[$uKey])) {
                $problems[] = "username \"{$username}\" is also on line {$seenUsernames[$uKey]}";
            }
            if ($email !== '' && isset($seenEmails[$eKey])) {
                $problems[] = "email {$email} is also on line {$seenEmails[$eKey]}";
            }
            $seenUsernames[$uKey] ??= $lineNo;
            $seenEmails[$eKey] ??= $lineNo;
            if ($username !== '' || $email !== '') {
                $taken->execute(['u' => $username, 'e' => $email]);
                if ($existing = $taken->fetch()) {
                    $problems[] = mb_strtolower((string)$existing['username']) === $uKey
                        ? "username \"{$username}\" is already in use" : "email {$email} is already in use";
                }
            }

            $org = null;
            if ($orgName !== '') {
                $org = $orgsByName[mb_strtolower($orgName)] ?? null;
                if ($org === null) {
                    $problems[] = "no organisation called \"{$orgName}\"";
                }
            }
            $tagIds = [];
            foreach ($tagNames as $t) {
                if (!isset($tagsByName[mb_strtolower($t)])) {
                    $problems[] = "no tag called \"{$t}\"";
                } else {
                    $tagIds[] = $tagsByName[mb_strtolower($t)];
                }
            }
            if (!in_array($orgAdminRaw, ['', 'yes', 'no', 'y', 'n', 'true', 'false', '1', '0'], true)) {
                $problems[] = "org_admin must be yes or no, not \"{$orgAdminRaw}\"";
            }
            $orgAdmin = in_array($orgAdminRaw, ['yes', 'y', 'true', '1'], true);
            if ($orgAdmin && $orgName === '') {
                $problems[] = 'org_admin needs an organisation';
            }
            if ($tagIds === [] && $tagNames === [] && ($org === null ? $orgName === '' : $org['tag_ids'] === [])) {
                $problems[] = 'the account would see no data - give it tags or an organisation that has tags';
            }

            if ($problems !== []) {
                $errors[] = "Line {$lineNo}: " . implode('; ', $problems) . '.';
                continue;
            }
            if ($org !== null) {
                $addingPerOrg[$org['id']] = ($addingPerOrg[$org['id']] ?? 0) + 1;
            }
            $rows[] = [
                'line' => $lineNo, 'username' => $username, 'email' => $email,
                'organisation_id' => $org['id'] ?? null, 'organisation' => $org['name'] ?? null,
                'tag_ids' => array_values(array_unique($tagIds)), 'tags' => $tagNames, 'org_admin' => $orgAdmin,
            ];
        }

        $warnings = [];
        foreach ($addingPerOrg as $id => $n) {
            if (!OrganisationRepository::hasRoom($id, $n)) {
                $org = OrganisationRepository::get($id);
                $warnings[] = "{$org['name']} will have " . ($org['active_users'] + $n) . " active users, over its limit of {$org['max_users']}.";
            }
        }
        return ['rows' => $errors === [] ? $rows : [], 'errors' => $errors, 'warnings' => $warnings];
    }

    /**
     * Creates the parsed accounts and (optionally) emails each a setup link.
     *
     * @param callable(int $userId, string $email, string $username): bool $sendSetupLink
     * @return array{created: string[], email_failed: string[], failed: string[]}
     */
    public static function run(array $rows, bool $sendEmails, callable $sendSetupLink): array
    {
        $result = ['created' => [], 'email_failed' => [], 'failed' => []];
        foreach ($rows as $row) {
            try {
                $id = UserRepository::createUser($row['username'], $row['email'], false, $row['tag_ids'], false, $row['organisation_id'], $row['org_admin']);
            } catch (\RuntimeException $e) {
                // Taken between checking and creating - report and carry on.
                $result['failed'][] = "Line {$row['line']} ({$row['username']}): " . $e->getMessage();
                continue;
            }
            $result['created'][] = $row['username'];
            if ($sendEmails && !$sendSetupLink($id, $row['email'], $row['username'])) {
                $result['email_failed'][] = $row['username'];
            }
        }
        return $result;
    }
}
