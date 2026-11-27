<?php
declare(strict_types=1);

namespace VulnDash\Lib;

/**
 * Qualys already has a tag with the name a set-up asked for, so nothing was
 * created and the admin has to choose: use that tag, or delete the set-up and pick
 * another name (AgentProvisioner::ensureTag()).
 */
final class AgentTagExistsException extends \RuntimeException
{
    /**
     * @param array<int, array<string, mixed>> $matches Qualys tag id => tag (QualysApiClient::searchTagsByIds() shape)
     */
    public function __construct(public readonly int $provisioningId, public readonly string $tagName, public readonly array $matches)
    {
        $static = array_filter($matches, static fn (array $t): bool => $t['ruleType'] === null && $t['srcAssetGroupId'] === null);
        parent::__construct("Qualys already has a tag called {$tagName} (tag id " . implode(', ', array_keys($matches)) . '), so nothing was created. '
            . ($static !== []
                ? 'Use that tag for this client, or delete this set-up and choose another name.'
                : 'It has dynamic rules, which an activation key can\'t apply - delete this set-up and choose another name.'));
    }
}
