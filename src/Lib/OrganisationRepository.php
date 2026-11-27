<?php
declare(strict_types=1);

namespace VulnDash\Lib;

/**
 * Client organisations (2026-11) - see database/migrations/2026-11-add-organisations.sql.
 *
 * An organisation groups a client's accounts and the tags they all see. Its
 * members' access is their own per-user extras plus these tags
 * (UserRepository::EFFECTIVE_TAGS_SQL), so changing an organisation's tags
 * changes every member's access on their next request. Suspending it signs
 * every member out and stops them signing in. max_users caps how many ACTIVE
 * accounts its organisation admins can have (Plainsight admins can go past it).
 */
final class OrganisationRepository
{
    /**
     * @return array<int, array{id: int, name: string, is_active: bool, max_users: ?int, tag_ids: int[], tag_names: string,
     *                          active_users: int, total_users: int, org_admins: int}>
     */
    public static function listAll(): array
    {
        $rows = Database::getConnection()->query("
            SELECT o.id, o.name, o.is_active, o.max_users, o.expires_on,
                   (SELECT GROUP_CONCAT(ot.tag_id) FROM organisation_tags ot WHERE ot.organisation_id = o.id) AS tag_ids,
                   (SELECT GROUP_CONCAT(t.name ORDER BY t.name SEPARATOR ', ') FROM organisation_tags ot JOIN tags t ON t.id = ot.tag_id
                    WHERE ot.organisation_id = o.id) AS tag_names,
                   (SELECT COUNT(*) FROM users u WHERE u.organisation_id = o.id AND u.is_active = 1) AS active_users,
                   (SELECT COUNT(*) FROM users u WHERE u.organisation_id = o.id) AS total_users,
                   (SELECT COUNT(*) FROM users u WHERE u.organisation_id = o.id AND u.is_org_admin = 1) AS org_admins
            FROM organisations o
            ORDER BY o.name
        ")->fetchAll();
        return array_map([self::class, 'shape'], $rows);
    }

    public static function get(int $id): ?array
    {
        foreach (self::listAll() as $org) {
            if ($org['id'] === $id) {
                return $org;
            }
        }
        return null;
    }

    /**
     * @param int[] $tagIds
     * @throws \RuntimeException on a duplicate name
     */
    public static function create(string $name, array $tagIds, ?int $maxUsers): int
    {
        $pdo = Database::getConnection();
        $pdo->beginTransaction();
        try {
            $pdo->prepare('INSERT INTO organisations (name, max_users) VALUES (:name, :max)')
                ->execute(['name' => $name, 'max' => $maxUsers]);
            $id = (int)$pdo->lastInsertId();
            self::writeTags($pdo, $id, $tagIds);
            $pdo->commit();
            return $id;
        } catch (\PDOException $e) {
            $pdo->rollBack();
            throw self::friendly($e);
        }
    }

    /** @param int[] $tagIds */
    public static function update(int $id, string $name, array $tagIds, ?int $maxUsers): void
    {
        $pdo = Database::getConnection();
        $pdo->beginTransaction();
        try {
            $pdo->prepare('UPDATE organisations SET name = :name, max_users = :max WHERE id = :id')
                ->execute(['name' => $name, 'max' => $maxUsers, 'id' => $id]);
            self::writeTags($pdo, $id, $tagIds);
            $pdo->commit();
        } catch (\PDOException $e) {
            $pdo->rollBack();
            throw self::friendly($e);
        }
    }

    /**
     * Sets (or clears, with null) the organisation's access end date - the
     * last day its members can sign in. See AccessExpiry.
     */
    public static function setExpiresOn(int $id, ?string $date): void
    {
        Database::getConnection()->prepare('UPDATE organisations SET expires_on = :d WHERE id = :id')
            ->execute(['d' => $date, 'id' => $id]);
    }

    public static function setActive(int $id, bool $active): void
    {
        Database::getConnection()->prepare('UPDATE organisations SET is_active = :a WHERE id = :id')
            ->execute(['a' => $active ? 1 : 0, 'id' => $id]);
    }

    /**
     * Deletes the organisation. Its accounts stay, with no organisation and
     * no organisation admin flag - they keep only their own extra tags.
     */
    public static function delete(int $id): void
    {
        $pdo = Database::getConnection();
        $pdo->prepare('UPDATE users SET is_org_admin = 0 WHERE organisation_id = :id')->execute(['id' => $id]);
        $pdo->prepare('DELETE FROM organisations WHERE id = :id')->execute(['id' => $id]);
    }

    public static function findByName(string $name): ?array
    {
        $stmt = Database::getConnection()->prepare('SELECT id FROM organisations WHERE name = :name');
        $stmt->execute(['name' => $name]);
        $id = $stmt->fetchColumn();
        return $id === false ? null : self::get((int)$id);
    }

    /**
     * Whether one more ACTIVE account fits under the organisation's limit.
     * Deactivated accounts don't count, so deactivating someone frees a
     * place - and reactivating them needs one.
     */
    public static function hasRoom(int $id, int $adding = 1): bool
    {
        $org = self::get($id);
        return $org !== null && ($org['max_users'] === null || $org['active_users'] + $adding <= $org['max_users']);
    }

    /** @param int[] $tagIds */
    private static function writeTags(\PDO $pdo, int $id, array $tagIds): void
    {
        $pdo->prepare('DELETE FROM organisation_tags WHERE organisation_id = :id')->execute(['id' => $id]);
        $insert = $pdo->prepare('INSERT IGNORE INTO organisation_tags (organisation_id, tag_id) VALUES (:org, :tag)');
        foreach (array_unique(array_map('intval', $tagIds)) as $tagId) {
            if ($tagId > 0) {
                $insert->execute(['org' => $id, 'tag' => $tagId]);
            }
        }
    }

    private static function friendly(\PDOException $e): \Throwable
    {
        if ((int)$e->getCode() === 23000 || str_contains($e->getMessage(), 'Duplicate entry')) {
            return new \RuntimeException('An organisation with that name already exists.');
        }
        return $e;
    }

    private static function shape(array $r): array
    {
        return [
            'id'           => (int)$r['id'],
            'name'         => (string)$r['name'],
            'is_active'    => (int)$r['is_active'] === 1,
            'max_users'    => $r['max_users'] !== null ? (int)$r['max_users'] : null,
            'expires_on'   => $r['expires_on'] !== null ? (string)$r['expires_on'] : null,
            'tag_ids'      => $r['tag_ids'] !== null && $r['tag_ids'] !== '' ? array_map('intval', explode(',', (string)$r['tag_ids'])) : [],
            'tag_names'    => (string)($r['tag_names'] ?? ''),
            'active_users' => (int)$r['active_users'],
            'total_users'  => (int)$r['total_users'],
            'org_admins'   => (int)$r['org_admins'],
        ];
    }
}
