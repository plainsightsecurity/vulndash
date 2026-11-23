<?php
declare(strict_types=1);

namespace VulnDash\Lib;

/**
 * The Qualys Cloud Agent install commands offered by the Assets page's
 * "Install agent" overlay - the same one-liners used in the CE+ onboarding
 * instructions, with the tag's activation ID (tags.agent_activation_id, set
 * in Manage Users > Tags) filled in.
 *
 * The ID is spliced into a shell/PowerShell command that people paste into
 * an elevated terminal, so it's only ever accepted in canonical UUID form
 * (normaliseActivationId()) - nothing else can reach the command text, even
 * if a bad value somehow got into the database.
 */
final class AgentInstall
{
    private const WINDOWS_SCRIPT_URL = 'https://plainsightsecurity.co.uk/agents/installqualysagent.ps1';
    private const UNIX_SCRIPT_URL    = 'https://plainsightsecurity.co.uk/agents/installqualysagent';

    /**
     * Canonical lower-case 8-4-4-4-12 form, or null if $raw isn't a UUID.
     * Tolerates surrounding whitespace and upper case, as pasted from Qualys.
     */
    public static function normaliseActivationId(string $raw): ?string
    {
        $id = strtolower(trim($raw));
        return preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/', $id) === 1 ? $id : null;
    }

    /** PowerShell, run as Administrator. Null if the ID isn't a valid UUID. */
    public static function windowsCommand(string $activationId): ?string
    {
        $id = self::normaliseActivationId($activationId);
        if ($id === null) {
            return null;
        }
        // TLS 1.2 forced first: Windows PowerShell 5.1 on older builds still
        // defaults to TLS 1.0, which the site refuses.
        return '[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; '
            . 'iex "& { $(irm ' . self::WINDOWS_SCRIPT_URL . ') } -ActivationID ' . $id . '"';
    }

    /** macOS and Linux, from an account with sudo. Null if the ID isn't a valid UUID. */
    public static function unixCommand(string $activationId): ?string
    {
        $id = self::normaliseActivationId($activationId);
        if ($id === null) {
            return null;
        }
        return 'sudo curl -sSL ' . self::UNIX_SCRIPT_URL . ' | sudo bash -s ' . $id;
    }

    /**
     * The tags out of $tags (rows with id, name, agent_activation_id) that
     * have a usable activation ID, each with its two commands - what the
     * overlay offers. Empty means no "Install agent" button at all.
     *
     * @param array<int, array<string, mixed>> $tags
     * @return array<int, array{id: int, name: string, activation_id: string, windows: string, unix: string}>
     */
    public static function installableTags(array $tags): array
    {
        $out = [];
        foreach ($tags as $tag) {
            $id = self::normaliseActivationId((string)($tag['agent_activation_id'] ?? ''));
            if ($id === null) {
                continue;
            }
            $out[] = [
                'id'            => (int)$tag['id'],
                'name'          => (string)$tag['name'],
                'activation_id' => $id,
                'windows'       => (string)self::windowsCommand($id),
                'unix'          => (string)self::unixCommand($id),
            ];
        }
        return $out;
    }
}
