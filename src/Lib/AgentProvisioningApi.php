<?php
declare(strict_types=1);

namespace VulnDash\Lib;

/**
 * The Qualys calls AgentProvisioner needs. Implemented by
 * scripts/lib/QualysApiClient.php for real; an interface so the tests can run
 * the whole set-up flow against a stub without ever reaching Qualys.
 *
 * Tag arrays have the shape QualysApiClient::searchTagsByIds() returns
 * (name, ruleType, ruleText, srcAssetGroupId, parentTagId, other). Key arrays
 * are array{id: int, title: string, activation_key: string, tag_ids: int[]}.
 * Every method throws \RuntimeException on any failure, including a
 * non-SUCCESS response - nothing comes back looking like "no results".
 */
interface AgentProvisioningApi
{
    /**
     * Tags whose name contains $name, keyed by Qualys tag id. Callers compare
     * names themselves: whether Qualys matches case-insensitively isn't
     * documented, so this is only ever a superset of the exact matches.
     *
     * @return array<int, array<string, mixed>>
     */
    public function searchTagsByNameContains(string $name): array;

    /** Creates a static (rule-less) top-level tag and returns its Qualys id. */
    public function createStaticTag(string $name): int;

    /** @return array<int, array{id: int, title: string, activation_key: string, tag_ids: int[]}> every activation key, keyed by key id */
    public function listActivationKeys(): array;

    /**
     * Creates an unlimited activation key that applies one tag.
     *
     * @param string[] $modules Qualys licence names, e.g. VM_LICENSE
     * @return array{id: int, title: string, activation_key: string, tag_ids: int[]}
     */
    public function createActivationKey(string $title, int $tagId, string $tagName, array $modules): array;

    /** @return array{id: int, title: string, activation_key: string, tag_ids: int[]}|null null if Qualys has no key with that id */
    public function getActivationKey(int $keyId): ?array;
}
