<?php
declare(strict_types=1);

namespace VulnDash\Lib;

/**
 * Decides which of a host's Qualys tags may scope it, by how each tag is
 * built in Qualys.
 *
 * WHY THIS EXISTS. Tag scoping is per host: a tag on a host scopes every
 * finding on it. Qualys evaluates asset-group and IP-range tags against the
 * agent host's IP, so a tag made for an external scan of a client's servers
 * lands on the agent hosts with those IPs and puts all their internal agent
 * findings under it (2026-11, "FaiceTech Ce Ext 2026"). Until now the only
 * fix was adding each such tag's name to qualys.excluded_tags by hand.
 *
 * The rule (isIpBased()): a tag with a srcAssetGroupId, or a ruleType
 * starting NETWORK_RANGE, never scopes an agent host. Confirmed 2026-11
 * against this subscription: every client tag came back with no ruleType
 * (static); the asset-group tag had srcAssetGroupId set and ruleType
 * NETWORK_RANGE_ENHANCED - a value missing from Qualys's documented list,
 * which is why both fields are checked and the type is matched by prefix.
 * Every other dynamic type (GROOVY, ASSET_SEARCH, OS_REGEX...) still scopes,
 * by Mark's call: a rule on OS or software is a legitimate way to scope a
 * client. The known gap is a rule of one of those types written on IP
 * addresses - revisit if one turns up.
 *
 * Fail closed: a tag not yet classified (lookup not made, or Qualys didn't
 * return it) scopes nothing, so a new tag can never briefly leak findings
 * before its type is known.
 *
 * Classifications are cached in qualys_tag_rules (see its migration), so
 * Qualys is only asked about a tag id seen for the first time, plus one
 * refresh of every cached tag once qualys.tag_rule_refresh_hours (default
 * 24) has passed - in case a tag's rule is changed in Qualys. Each lookup is
 * one call per 100 ids. A failed lookup for a tag seen for the first time
 * throws, failing the run loudly (cursor kept, nothing lost); a failed
 * refresh only warns and keeps the cached answers.
 *
 * Used only by HostSyncWriter::upsertAssetAndTags(), the one place
 * asset_tags is written, so every reader of asset_tags is right without
 * changes and neither host job can bypass it.
 */
final class TagScopeClassifier
{
    public const DEFAULT_REFRESH_HOURS = 24;

    private \PDO $pdo;

    /** @var (callable(array<int,string>): array<int,array>)|null Qualys Search Tags lookup - see QualysApiClient::searchTagsByIds() */
    private $lookup;

    private int $refreshHours;

    /** @var array<string,array{found:bool,is_ip_based:bool,name:?string,checked_at:string}>|null qualys tag id => cached row; null until first loaded */
    private ?array $cache = null;

    private bool $refreshAttempted = false;

    /** @var array<string,true> stored tags.qualys_tag_id values with no cached rule - asked about alongside the first new id, see ensureClassified() */
    private array $storedUnclassified = [];

    /** @var array<string,array{name:string,hosts:int}> IP-based tags kept off hosts this run */
    private array $keptOff = [];

    /** @var array<string,array{name:string,hosts:int}> unclassified tags kept off hosts this run */
    private array $unclassified = [];

    /** @var string[] */
    private array $warnings = [];

    private int $lookupCalls = 0;

    /**
     * @param callable|null $lookup fn(array $qualysTagIds): array, shaped like
     *        QualysApiClient::searchTagsByIds(). Null means cache only: an
     *        uncached tag stays unclassified and scopes nothing.
     */
    public function __construct(\PDO $pdo, ?callable $lookup, ?int $refreshHours = null)
    {
        $this->pdo = $pdo;
        $this->lookup = $lookup;
        $this->refreshHours = max(1, $refreshHours ?? (int)(Config::get('qualys.tag_rule_refresh_hours') ?? self::DEFAULT_REFRESH_HOURS));
    }

    /**
     * The one copy of the rule - see the class docblock.
     */
    public static function isIpBased(?string $ruleType, ?int $srcAssetGroupId): bool
    {
        return $srcAssetGroupId !== null
            || ($ruleType !== null && str_starts_with(strtoupper($ruleType), 'NETWORK_RANGE'));
    }

    /**
     * The subset of one host's tags allowed to scope it. Looks up any tag id
     * not cached yet first (and refreshes stale ones on the first call that
     * finds any).
     *
     * @param array<int,array{qualys_tag_id:string,name:string}> $tags
     * @return array<int,array{qualys_tag_id:string,name:string}>
     */
    public function scopingTags(array $tags): array
    {
        if ($tags === []) {
            return [];
        }
        $this->ensureClassified(array_map(static fn(array $t): string => (string)$t['qualys_tag_id'], $tags));

        $allowed = [];
        foreach ($tags as $tag) {
            $id = (string)$tag['qualys_tag_id'];
            $row = $this->cache[$id] ?? null;
            if ($row === null || !$row['found']) {
                $this->count($this->unclassified, $id, $tag['name']);
            } elseif ($row['is_ip_based']) {
                $this->count($this->keptOff, $id, $tag['name']);
            } else {
                $allowed[] = $tag;
            }
        }
        return $allowed;
    }

    /**
     * One line for the job's log: what was kept off hosts this run, and any
     * refresh warning. Empty string when there's nothing to say.
     */
    public function logLine(): string
    {
        $out = '';
        $fmt = static fn(array $set): string => implode(', ', array_map(
            static fn(array $t): string => "{$t['name']} ({$t['hosts']} host" . ($t['hosts'] === 1 ? '' : 's') . ')',
            array_values($set)
        ));
        if ($this->keptOff !== []) {
            $out .= 'Tag scope: asset-group/IP-range tag(s) kept off agent hosts: ' . $fmt($this->keptOff) . "\n";
        }
        if ($this->unclassified !== []) {
            $out .= 'Tag scope: WARNING - tag(s) Qualys has not classified (not returned by Search Tags), so scoping nothing: ' . $fmt($this->unclassified) . "\n";
        }
        foreach ($this->warnings as $w) {
            $out .= "Tag scope: WARNING - {$w}\n";
        }
        if ($this->lookupCalls > 0) {
            $out .= "Tag scope: {$this->lookupCalls} Search Tags lookup(s) made this run.\n";
        }
        return $out;
    }

    /** @param string[] $ids */
    private function ensureClassified(array $ids): void
    {
        $this->loadCache();

        $missing = [];
        foreach ($ids as $id) {
            if (!isset($this->cache[$id])) {
                $missing[$id] = true;
            }
        }

        $stale = [];
        if (!$this->refreshAttempted && $this->lookup !== null) {
            $cutoff = (new \DateTimeImmutable())->modify("-{$this->refreshHours} hours")->format('Y-m-d H:i:s');
            foreach ($this->cache as $id => $row) {
                if ($row['checked_at'] < $cutoff) {
                    $stale[(string)$id] = true;
                }
            }
            if ($stale !== []) {
                // One refresh per run, whether or not it works - a failing
                // endpoint shouldn't cost a call on every host.
                $this->refreshAttempted = true;
            }
        }

        if (($missing === [] && $stale === []) || $this->lookup === null) {
            return;
        }

        // Any lookup also takes every stored tag not classified yet, so the
        // first run after deployment classifies the whole estate in one call
        // rather than one per host that brings a new id.
        if ($missing !== []) {
            $missing += array_diff_key($this->storedUnclassified, $this->cache);
            $this->storedUnclassified = [];
        }

        $ask = array_map('strval', array_keys($missing + $stale));
        try {
            $this->lookupCalls += (int)ceil(count($ask) / 100);
            $defs = ($this->lookup)($ask);
        } catch (\Throwable $e) {
            if ($missing !== []) {
                throw new \RuntimeException('Could not classify new Qualys tag id(s) ' . implode(', ', array_keys($missing))
                    . ' via Search Tags, so they cannot be allowed to scope hosts yet: ' . $e->getMessage(), 0, $e);
            }
            $this->warnings[] = 'daily refresh of tag rules failed, using cached rules: ' . $e->getMessage();
            return;
        }

        $this->store($ask, $defs);
    }

    /**
     * @param string[] $asked
     * @param array<int,array> $defs keyed by Qualys tag id
     */
    private function store(array $asked, array $defs): void
    {
        $stmt = $this->pdo->prepare('
            INSERT INTO qualys_tag_rules (qualys_tag_id, tag_name, rule_type, src_asset_group_id, found, is_ip_based, checked_at)
            VALUES (:qualys_tag_id, :tag_name, :rule_type, :src_asset_group_id, :found, :is_ip_based, :checked_at)
            ON DUPLICATE KEY UPDATE
                tag_name = VALUES(tag_name), rule_type = VALUES(rule_type), src_asset_group_id = VALUES(src_asset_group_id),
                found = VALUES(found), is_ip_based = VALUES(is_ip_based), checked_at = VALUES(checked_at)
        ');
        $now = date('Y-m-d H:i:s');
        foreach ($asked as $id) {
            $def = ctype_digit($id) ? ($defs[(int)$id] ?? null) : null;
            $ipBased = $def !== null && self::isIpBased($def['ruleType'] ?? null, $def['srcAssetGroupId'] ?? null);
            $stmt->execute([
                'qualys_tag_id'      => $id,
                'tag_name'           => $def['name'] ?? null,
                'rule_type'          => $def['ruleType'] ?? null,
                'src_asset_group_id' => $def['srcAssetGroupId'] ?? null,
                'found'              => $def !== null ? 1 : 0,
                'is_ip_based'        => $ipBased ? 1 : 0,
                'checked_at'         => $now,
            ]);
            $this->cache[$id] = ['found' => $def !== null, 'is_ip_based' => $ipBased, 'name' => $def['name'] ?? null, 'checked_at' => $now];
        }
    }

    private function loadCache(): void
    {
        if ($this->cache !== null) {
            return;
        }
        $this->cache = [];
        foreach ($this->pdo->query('SELECT qualys_tag_id, tag_name, found, is_ip_based, checked_at FROM qualys_tag_rules') as $row) {
            $this->cache[(string)$row['qualys_tag_id']] = [
                'found'       => (bool)$row['found'],
                'is_ip_based' => (bool)$row['is_ip_based'],
                'name'        => $row['tag_name'],
                'checked_at'  => (string)$row['checked_at'],
            ];
        }
        foreach ($this->pdo->query('SELECT qualys_tag_id FROM tags WHERE qualys_tag_id IS NOT NULL') as $row) {
            $id = trim((string)$row['qualys_tag_id']);
            if ($id !== '' && !isset($this->cache[$id])) {
                $this->storedUnclassified[$id] = true;
            }
        }
    }

    /** @param array<string,array{name:string,hosts:int}> $set */
    private function count(array &$set, string $id, string $name): void
    {
        $set[$id] ??= ['name' => $name, 'hosts' => 0];
        $set[$id]['hosts']++;
    }
}
