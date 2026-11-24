<?php
declare(strict_types=1);

namespace VulnDash\Lib;

class Helpers
{
    /** @var array<int, string> Qualys severity level => display label */
    public const SEVERITY_LABELS = [
        1 => 'Informational',
        2 => 'Low',
        3 => 'Medium',
        4 => 'High',
        5 => 'Critical',
    ];

    /** @var array<int, string> Qualys severity level => CSS class for badges/stripes */
    public const SEVERITY_CSS_CLASS = [
        1 => 'sev-info',
        2 => 'sev-low',
        3 => 'sev-medium',
        4 => 'sev-high',
        5 => 'sev-critical',
    ];

    public static function e(?string $value): string
    {
        return htmlspecialchars($value ?? '', ENT_QUOTES, 'UTF-8');
    }

    /**
     * Pattern for the HTML pattern attribute on email inputs - the browser-side
     * twin of emailError()'s domain-ending check, so a typo like ".co.u" is
     * flagged before the form is even submitted. (The pattern attribute is
     * implicitly anchored at both ends.)
     */
    public const EMAIL_INPUT_PATTERN = '[^@\\s]+@[^@\\s]+\\.([A-Za-z]{2,}|[Xx][Nn]--[A-Za-z0-9\\-]+)';

    /**
     * Checks an email address before it's saved on an account. Returns null
     * if it's fine, or a message to show the admin if not.
     *
     * FILTER_VALIDATE_EMAIL alone accepts typos like "someone@company.co.u"
     * (it doesn't care what the domain ends in), and Resend then rejects the
     * send with a 422 - which surfaced only as a failed setup email after the
     * account had already been created. So on top of that, the domain must
     * have at least one dot and end in a real-looking top-level domain: two
     * or more letters, or a punycode "xn--" label for internationalised TLDs.
     */
    public static function emailError(string $email): ?string
    {
        if ($email === '') {
            return 'An email address is required.';
        }
        if (filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
            return "\"{$email}\" isn't a valid email address.";
        }
        $domain = substr($email, strrpos($email, '@') + 1);
        if (!str_contains($domain, '.')) {
            return "\"{$email}\" is missing the end of its domain (for example .co.uk or .com) - check for a typo.";
        }
        $tld = substr($domain, strrpos($domain, '.') + 1);
        if (!preg_match('/^(?:[a-z]{2,}|xn--[a-z0-9-]+)$/i', $tld)) {
            return "\"{$email}\" ends in \".{$tld}\", which isn't a valid domain ending - check for a typo.";
        }
        return null;
    }

    public static function severityLabel(int $level): string
    {
        return self::SEVERITY_LABELS[$level] ?? 'Unknown';
    }

    public static function severityCssClass(int $level): string
    {
        return self::SEVERITY_CSS_CLASS[$level] ?? '';
    }

    public static function csrfToken(): string
    {
        if (empty($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        }
        return $_SESSION['csrf_token'];
    }

    public static function verifyCsrf(?string $token): bool
    {
        return !empty($token)
            && !empty($_SESSION['csrf_token'])
            && hash_equals($_SESSION['csrf_token'], $token);
    }

    /**
     * Simple one-shot flash message for the post/redirect/get pattern used
     * by the admin pages - set before a redirect, read (and cleared) on the
     * page the redirect lands on.
     */
    public static function setFlash(string $message, string $type = 'success'): void
    {
        $_SESSION['flash'] = ['message' => $message, 'type' => $type];
    }

    /** @return array{message: string, type: string}|null */
    public static function getFlash(): ?array
    {
        if (empty($_SESSION['flash'])) {
            return null;
        }
        $flash = $_SESSION['flash'];
        unset($_SESSION['flash']);
        return $flash;
    }

    /**
     * Resolves which tag (if any) the current page should be scoped to,
     * persisting the choice in the session so it carries across pages -
     * dashboard -> assets -> vulnerabilities -> back to dashboard - without
     * needing to be re-selected every time.
     *
     * One dropdown, one param (?view_tag=<id>) - this used to be split into
     * separate "Agent Tags"/"Scans" dropdowns (see UserRepository's former
     * tagTypeJoinSql(), removed 2026-07 when this became an agent-only
     * internal tool), but with only one kind of tag left there's nothing
     * left to split between.
     *
     * - The param present on the current request (even as an empty string,
     *   i.e. "All" picked from the dropdown) always wins over whatever was
     *   previously stored, and updates the stored preference.
     * - With the param absent entirely (e.g. following a plain link that
     *   doesn't mention tags), the last stored preference is used instead.
     * - Either way, the result is checked against $availableTagIds - a
     *   stored or requested tag ID outside that set (it was since deleted,
     *   or this account's own tag assignments changed) is dropped rather
     *   than applied.
     *
     * @param int[] $availableTagIds
     */
    public static function resolveViewTag(array $availableTagIds): ?int
    {
        if (isset($_GET['view_tag'])) {
            $_SESSION['view_tag_id'] = $_GET['view_tag'] !== '' ? (int)$_GET['view_tag'] : null;
        }

        $viewTagId = $_SESSION['view_tag_id'] ?? null;

        if ($viewTagId !== null && !in_array($viewTagId, $availableTagIds, true)) {
            $viewTagId = null;
        }

        return $viewTagId;
    }

    /**
     * Formats a DATETIME that's already stored in Europe/London wall-clock
     * time (which is now everything this app writes itself - see
     * bootstrap.php and Database::getConnection()) with an explicit
     * BST/GMT label, so a displayed value is never ambiguous about which
     * one it is. This does NOT convert anything - it just attaches the
     * correct label for whichever zone that specific date falls in.
     *
     * Only ever use this on the way out to HTML. Never store, compare, or
     * feed its output back into a query or sync_log cursor.
     *
     * For the six Qualys-sourced columns that are still stored in UTC
     * (published_datetime, qualys_last_modified, first_found, last_found,
     * last_fixed, last_scan_date - see QualysApiClient::toMysqlDatetime(),
     * which deliberately normalises Qualys's own 'Z'-suffixed timestamps
     * with gmdate()), use displayQualysDateTime() instead - using this
     * function on one of those would show the raw UTC value mislabelled
     * as local time, an hour off for half the year.
     */
    public static function displayDateTime(?string $localDatetime, string $format = 'Y-m-d H:i:s T'): string
    {
        if ($localDatetime === null || $localDatetime === '') {
            return '—';
        }

        try {
            $dt = new \DateTimeImmutable($localDatetime, new \DateTimeZone('Europe/London'));
        } catch (\Exception $e) {
            // Shouldn't happen for anything actually stored in a DATETIME
            // column, but fall back to the raw value rather than hiding
            // a malformed one behind a bare em dash.
            return $localDatetime;
        }

        return $dt->format($format);
    }

    /**
     * Same as displayDateTime(), but for the six columns that are still
     * stored in UTC because they come straight from Qualys - see the
     * docblock on displayDateTime() for which ones and why. Converts
     * UTC -> Europe/London (DST-aware, via tzdata) before formatting.
     */
    public static function displayQualysDateTime(?string $utcDatetime, string $format = 'Y-m-d H:i:s T'): string
    {
        if ($utcDatetime === null || $utcDatetime === '') {
            return '—';
        }

        try {
            $dt = new \DateTimeImmutable($utcDatetime, new \DateTimeZone('UTC'));
        } catch (\Exception $e) {
            return $utcDatetime;
        }

        return $dt->setTimezone(new \DateTimeZone('Europe/London'))->format($format);
    }

    /**
     * "3 minutes ago" / "2 hours ago" / "5 days ago" style relative time,
     * for the admin-only sync status panel where how long it's actually
     * been matters more than the exact timestamp at a glance.
     */
    public static function relativeTime(?string $datetime): string
    {
        if ($datetime === null) {
            return 'never';
        }

        $seconds = max(0, time() - strtotime($datetime));

        if ($seconds < 60) {
            return 'just now';
        }

        $minutes = (int)floor($seconds / 60);
        if ($minutes < 60) {
            return $minutes . ' minute' . ($minutes === 1 ? '' : 's') . ' ago';
        }

        $hours = (int)floor($minutes / 60);
        if ($hours < 24) {
            return $hours . ' hour' . ($hours === 1 ? '' : 's') . ' ago';
        }

        $days = (int)floor($hours / 24);
        return $days . ' day' . ($days === 1 ? '' : 's') . ' ago';
    }

    /**
     * Renders one sortable <th>'s clickable label - used by assets.php and
     * vulnerabilities.php for every column header. Clicking a column that
     * isn't the current sort starts it ascending; clicking the current
     * sort column again flips it to descending, then back to ascending,
     * and so on. The link always carries every other current GET param
     * (filters, search term) forward unchanged, and always drops `page` -
     * a new sort order makes whatever page you were on largely
     * meaningless, so this resets to page 1 rather than stranding you on,
     * say, page 4 of a completely different ordering.
     *
     * $sortKey must be one of VulnerabilityRepository::ASSET_SORT_COLUMNS
     * or ::DETECTION_SORT_COLUMNS's keys (whichever list applies to the
     * calling page) - this function only ever builds a link, the
     * repository's own whitelist is what actually protects the query.
     */
    public static function sortLink(string $label, string $sortKey, ?string $currentSort, string $currentDir): string
    {
        $nextDir = ($currentSort === $sortKey && $currentDir === 'asc') ? 'desc' : 'asc';

        $query = $_GET;
        unset($query['page']);
        $query['sort'] = $sortKey;
        $query['dir'] = $nextDir;

        $href = '?' . self::e(http_build_query($query));

        $indicator = '';
        if ($currentSort === $sortKey) {
            $indicator = ' <span class="sort-indicator">' . ($currentDir === 'asc' ? '&#9650;' : '&#9660;') . '</span>';
        }

        return '<a class="sort-link" href="' . $href . '">' . self::e($label) . '</a>' . $indicator;
    }

    /**
     * Turns the current tag scope into the human-readable label used
     * throughout the Reports feature (reports.php's preview, and the
     * "Scope:" line on both the PDF and CSV exports) - "All tags" for an
     * unfiltered admin, "Your assigned tags" for an unfiltered non-admin,
     * or the specific tag's name once $viewTagId narrows either of those
     * down to one tag. Deliberately takes the same $availableTags list the
     * calling page already built for its own dropdown (UserRepository::
     * listTags()/getTagsByIds()) rather than querying again here.
     *
     * @param array<int, array<string, mixed>> $availableTags
     */
    public static function scopeLabel(array $availableTags, ?int $viewTagId, bool $isAdmin): string
    {
        if ($viewTagId !== null) {
            foreach ($availableTags as $tag) {
                if ((int)$tag['id'] === $viewTagId) {
                    return (string)$tag['name'];
                }
            }
        }

        return $isAdmin ? 'All tags' : 'Your assigned tags';
    }

    /**
     * Plain-English description of the severity/CE+ filters applied to a
     * report export, e.g. "Severity: Critical, CE+ failures only" - used
     * for the "Filters applied:" line on both the PDF and CSV exports so
     * the document itself records what it does and doesn't include,
     * without the reader needing to know this app's query-string
     * parameters. Returns an empty string (not an empty array) when
     * nothing is applied, since every call site just wants a single line
     * of text ("None" is substituted by the caller in that case).
     */
    public static function describeReportFilters(?int $severity, bool $cePlusOnly): string
    {
        $parts = [];
        if ($severity !== null) {
            $parts[] = 'Severity: ' . self::severityLabel($severity);
        }
        if ($cePlusOnly) {
            $parts[] = 'CE+ failures only (CVSS >= 7.0)';
        }
        return implode(', ', $parts);
    }

    /**
     * Neutralises spreadsheet formula injection for a single CSV cell value.
     *
     * Excel/LibreOffice/Google Sheets treat a cell whose text begins with
     * =, +, -, @, or a leading tab/carriage return as a *formula*, so a
     * value like `=HYPERLINK(...)` or `=cmd|'/c calc'!A1` pulled from an
     * external source (a Qualys-sourced finding title, an asset hostname or
     * DNS name that ultimately reflects attacker-influenced data, etc.) can
     * execute when the exported file is opened. Prefixing any such value
     * with a single apostrophe forces the spreadsheet to treat the whole
     * cell as literal text - the apostrophe itself is not shown as data by
     * those applications - while leaving ordinary values completely
     * untouched. Non-string values (already-cast ints/floats) are returned
     * as-is, since only free-text fields can carry this.
     *
     * See OWASP "CSV Injection" (aka Formula Injection). Applied in
     * public/report_csv.php to every free-text column of the export.
     */
    public static function csvSafe(?string $value): string
    {
        if ($value === null || $value === '') {
            return '';
        }
        // A leading =, +, -, @, tab (\t), CR (\r) or LF (\n) is the trigger.
        if (preg_match('/^[=+\-@\t\r\n]/', $value) === 1) {
            return "'" . $value;
        }
        return $value;
    }

    /**
     * Encodes an arbitrary string for safe interpolation into a JavaScript
     * string context that itself sits inside a double-quoted HTML attribute
     * - specifically the inline `onsubmit="return confirm(...)"` handlers on
     * the admin pages, whose message text includes account/tag names.
     *
     * Escaping such a value with the ordinary HTML escaper (Helpers::e())
     * is NOT enough here: the HTML parser decodes entities like `&#039;`
     * back to a bare `'` before the JavaScript engine ever sees the handler
     * source, so an entity-escaped apostrophe still terminates the JS string
     * literal and lets the rest of the value run as script (a stored-XSS
     * vector, since a tag name can originate from a Qualys-reported tag).
     *
     * json_encode() produces a fully-quoted JS string literal with every
     * JS-significant character escaped; the HEX flags additionally escape
     * <, >, &, ', and " to their \uXXXX forms so nothing inside can close
     * the attribute or the surrounding <script>. Running the result through
     * htmlspecialchars() then makes json_encode's own delimiting double
     * quotes attribute-safe. The output already INCLUDES the surrounding
     * quotes, so call sites drop it straight into confirm(...) with no
     * quotes of their own:
     *     onsubmit="return confirm(<?= Helpers::jsAttr($msg) ?>);"
     */
    public static function jsAttr(?string $value): string
    {
        $json = json_encode(
            (string)($value ?? ''),
            JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP | JSON_UNESCAPED_UNICODE
        );
        if ($json === false) {
            $json = '""';
        }
        return htmlspecialchars($json, ENT_QUOTES, 'UTF-8');
    }

    // Tags kept as-is by sanitizeVendorHtml() - enough to preserve Qualys's
    // own multi-step remediation formatting (paragraphs, lists, tables,
    // inline emphasis, reference links) without allowing anything active.
    private const VENDOR_HTML_ALLOWED_TAGS = [
        'p', 'br', 'hr', 'ul', 'ol', 'li', 'dl', 'dt', 'dd',
        'b', 'strong', 'i', 'em', 'u', 's', 'strike', 'sub', 'sup', 'small',
        'code', 'pre', 'kbd', 'samp', 'tt', 'blockquote', 'q', 'cite', 'abbr',
        'a', 'span', 'div', 'section', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
        'table', 'thead', 'tbody', 'tfoot', 'tr', 'td', 'th', 'caption',
    ];

    // Elements dropped outright, subtree and all (as opposed to unknown-but-
    // harmless tags like <font>, which are unwrapped so their text survives).
    private const VENDOR_HTML_DROP_TAGS = [
        'script', 'style', 'iframe', 'object', 'embed', 'form', 'input',
        'button', 'textarea', 'select', 'option', 'link', 'meta', 'base',
        'svg', 'math', 'template', 'noscript', 'frame', 'frameset', 'applet',
    ];

    /** @var array<string, string[]> per-tag attribute allowlist; every other attribute is stripped */
    private const VENDOR_HTML_ALLOWED_ATTRS = [
        'a'  => ['href', 'title'],
        'td' => ['colspan', 'rowspan'],
        'th' => ['colspan', 'rowspan'],
        'abbr' => ['title'],
    ];

    /**
     * Allowlist-sanitises a fragment of vendor-supplied HTML (Qualys
     * KnowledgeBase diagnosis / consequence / solution text) so it can be
     * rendered with its intended formatting intact but WITHOUT trusting it
     * as active markup.
     *
     * The Qualys fields arrive as pre-formatted HTML (<P>, <UL><LI>, tables,
     * links) and rendering them raw is what makes multi-step remediation
     * readable - but "vendor-supplied" is not the same as "safe to inject
     * verbatim into an authenticated, multi-tenant page." Anything active in
     * that stream (a <script>, an onerror= handler, a javascript: href)
     * would become stored XSS affecting every account, admins included. This
     * strips exactly those while keeping the formatting: unknown tags are
     * unwrapped (text kept), a fixed dangerous set is dropped subtree-and-all,
     * every event-handler / style / class attribute is removed, and <a>
     * hrefs are limited to http/https/mailto/relative (no javascript:/data:).
     *
     * Fails CLOSED: if the DOM extension is unavailable or the fragment
     * can't be parsed, the whole value is HTML-escaped (formatting lost, but
     * never executed) rather than emitted raw.
     */
    public static function sanitizeVendorHtml(?string $html): string
    {
        if ($html === null) {
            return '';
        }
        $trimmed = trim($html);
        if ($trimmed === '') {
            return '';
        }

        // Fail closed when we can't parse: escape rather than emit raw.
        if (!class_exists('DOMDocument')) {
            return nl2br(self::e($html));
        }

        $doc = new \DOMDocument('1.0', 'UTF-8');
        $prevErrors = libxml_use_internal_errors(true);

        // The leading XML processing instruction forces loadHTML to treat the
        // bytes as UTF-8 (it otherwise assumes ISO-8859-1). The single wrapper
        // element gives us one predictable root to walk and serialise back.
        // NOIMPLIED/NODEFDTD stop loadHTML adding <html>/<body>/<!DOCTYPE>.
        $wrapped = '<?xml encoding="utf-8"?><div data-vd-root="1">' . $html . '</div>';
        $ok = $doc->loadHTML(
            $wrapped,
            LIBXML_NOERROR | LIBXML_NOWARNING | LIBXML_NONET | LIBXML_HTML_NOIMPLIED | LIBXML_HTML_NODEFDTD
        );
        libxml_clear_errors();
        libxml_use_internal_errors($prevErrors);

        if (!$ok) {
            return nl2br(self::e($html));
        }

        // Locate our wrapper div (skip the stray XML PI node if present).
        $root = null;
        foreach ($doc->childNodes as $node) {
            if ($node instanceof \DOMElement && $node->tagName === 'div') {
                $root = $node;
                break;
            }
        }
        if ($root === null) {
            return nl2br(self::e($html));
        }

        self::sanitizeVendorChildren($root);

        $out = '';
        foreach ($root->childNodes as $child) {
            $out .= $doc->saveHTML($child);
        }
        return $out;
    }

    /**
     * Depth-first cleaner for sanitizeVendorHtml(). Iterates a *snapshot* of
     * each parent's children (the live NodeList mutates as we drop/unwrap),
     * cleaning grandchildren before deciding what to do with the child, so an
     * unwrapped element's surviving children are already sanitised.
     */
    private static function sanitizeVendorChildren(\DOMNode $parent): void
    {
        $children = [];
        foreach ($parent->childNodes as $child) {
            $children[] = $child;
        }

        foreach ($children as $node) {
            if ($node instanceof \DOMElement) {
                self::sanitizeVendorChildren($node);
                self::sanitizeVendorElement($node);
            } elseif ($node instanceof \DOMText || $node instanceof \DOMDocumentFragment) {
                // Plain text is kept verbatim (DOM already decoded entities;
                // saveHTML re-encodes on the way out).
                continue;
            } else {
                // Comments, CDATA, processing instructions - drop them.
                $parent->removeChild($node);
            }
        }
    }

    private static function sanitizeVendorElement(\DOMElement $el): void
    {
        $tag = strtolower($el->tagName);
        $parent = $el->parentNode;
        if ($parent === null) {
            return;
        }

        // 1. Dangerous element - remove it and everything under it.
        if (in_array($tag, self::VENDOR_HTML_DROP_TAGS, true)) {
            $parent->removeChild($el);
            return;
        }

        // 2. Unknown-but-not-dangerous tag - unwrap: splice its (already
        //    cleaned) children in where it stood, then drop the element.
        if (!in_array($tag, self::VENDOR_HTML_ALLOWED_TAGS, true)) {
            while ($el->firstChild !== null) {
                $parent->insertBefore($el->firstChild, $el);
            }
            $parent->removeChild($el);
            return;
        }

        // 3. Allowed tag - strip every attribute not explicitly permitted
        //    (this alone removes on* handlers, style=, class=, id=, etc).
        $allowed = self::VENDOR_HTML_ALLOWED_ATTRS[$tag] ?? [];
        $attrNames = [];
        foreach ($el->attributes as $attr) {
            $attrNames[] = $attr->nodeName;
        }
        foreach ($attrNames as $name) {
            if (!in_array(strtolower($name), $allowed, true)) {
                $el->removeAttribute($name);
            }
        }

        // 4. <a href> - allow only safe schemes; neutralise the rest.
        if ($tag === 'a' && $el->hasAttribute('href')) {
            if (!self::isSafeUrl($el->getAttribute('href'))) {
                $el->removeAttribute('href');
            } else {
                // Any link we keep opens safely if a browser treats it as
                // external; harmless on same-origin links too.
                $el->setAttribute('rel', 'noopener noreferrer nofollow');
                // Off-site links (vendor advisories, patch downloads) open in
                // a new tab so the reader doesn't lose the finding they were
                // reading. Set here rather than allowed through from the
                // source, so it can't be supplied with another value.
                // Relative links and #anchors stay in the same tab.
                if (self::isOffsiteUrl($el->getAttribute('href'))) {
                    $el->setAttribute('target', '_blank');
                }
            }
        }
    }

    /**
     * True if a URL is safe to keep on an <a href> in sanitised vendor HTML:
     * relative links and anchors, or absolute http/https/mailto. Rejects
     * javascript:, data:, vbscript:, file: and anything else with a scheme,
     * after decoding entities and stripping the embedded control characters
     * sometimes used to smuggle a scheme past naive checks.
     */
    private static function isSafeUrl(string $url): bool
    {
        $decoded = html_entity_decode($url, ENT_QUOTES, 'UTF-8');
        // Strip all C0 control chars and spaces that could obfuscate a scheme
        // (e.g. "java\tscript:"), matching how browsers collapse them.
        $stripped = preg_replace('/[\x00-\x20]+/', '', $decoded) ?? '';

        // No scheme (relative path, query, or #anchor) is fine.
        if (!preg_match('/^([a-z][a-z0-9+.\-]*):/i', $stripped, $m)) {
            return true;
        }
        return in_array(strtolower($m[1]), ['http', 'https', 'mailto'], true);
    }

    /**
     * True for an absolute http(s) or protocol-relative (//host/...) URL -
     * the links that leave the dashboard and so open in a new tab. mailto:,
     * relative paths and #anchors are not off-site. Only called on URLs that
     * have already passed isSafeUrl().
     */
    private static function isOffsiteUrl(string $url): bool
    {
        $decoded = html_entity_decode($url, ENT_QUOTES, 'UTF-8');
        $stripped = preg_replace('/[\x00-\x20]+/', '', $decoded) ?? '';
        return preg_match('~^(https?:)?//~i', $stripped) === 1;
    }

    /**
     * Escapes plain text for HTML and turns any http/https URL in it into a
     * clickable link - for custom remediation saved before the rich-text
     * editor (content_format = 'text', see CustomRemediationRepository),
     * which is shown as escaped plain text but routinely carries vendor
     * advisory links.
     *
     * Only http(s) is linked, so nothing typed into the field can produce a
     * javascript:/data: href. Trailing sentence punctuation, and a closing
     * bracket with no opening partner inside the URL, are left outside the
     * link - so "see https://x/y." and "(https://x/y)" link just the URL.
     */
    public static function linkifyPlainText(?string $text): string
    {
        $text = $text ?? '';
        $parts = preg_split('~(https?://[^\s<>"\'`]+)~i', $text, -1, PREG_SPLIT_DELIM_CAPTURE);
        if ($parts === false) {
            return self::e($text);
        }

        $out = '';
        foreach ($parts as $i => $part) {
            if ($i % 2 === 0) {
                $out .= self::e($part);
                continue;
            }

            $url = $part;
            $trail = '';
            while ($url !== '') {
                $last = substr($url, -1);
                if (strpbrk($last, '.,;:!?') !== false
                    || ($last === ')' && substr_count($url, '(') < substr_count($url, ')'))
                    || ($last === ']' && substr_count($url, '[') < substr_count($url, ']'))
                ) {
                    $trail = $last . $trail;
                    $url = substr($url, 0, -1);
                    continue;
                }
                break;
            }

            // Always off-site (only http(s) is linked), so always a new tab -
            // same as sanitizeVendorHtml().
            $out .= '<a href="' . self::e($url) . '" target="_blank" rel="noopener noreferrer nofollow">' . self::e($url) . '</a>' . self::e($trail);
        }
        return $out;
    }

    /**
     * Converts a pre-rich-text (content_format = 'text') custom remediation
     * into equivalent HTML, so it can be loaded into the rich-text editor
     * without losing its layout: blank-line-separated blocks become <p>,
     * single line breaks become <br>, and URLs become links (via
     * linkifyPlainText(), so everything else is escaped).
     */
    public static function plainTextToHtml(string $text): string
    {
        $text = str_replace(["\r\n", "\r"], "\n", trim($text));
        if ($text === '') {
            return '';
        }

        $paragraphs = preg_split('/\n\s*\n/', $text) ?: [$text];
        $out = '';
        foreach ($paragraphs as $para) {
            $out .= '<p>' . str_replace("\n", '<br>', self::linkifyPlainText(trim($para))) . '</p>';
        }
        return $out;
    }

    /**
     * True when an HTML fragment has no visible text - e.g. the "<p>&nbsp;</p>"
     * a rich-text editor submits when cleared. Used to refuse saving an empty
     * custom remediation, which would otherwise be indistinguishable from
     * having no override at all.
     */
    public static function htmlIsBlank(string $html): bool
    {
        $text = html_entity_decode(strip_tags($html), ENT_QUOTES | ENT_HTML5, 'UTF-8');
        return trim($text, " \t\n\r\0\x0B\u{00A0}") === '';
    }

    /**
     * Rounds a chart's data maximum up to a "nice" axis ceiling (1/2/5 x a
     * power of ten - the same stepping spreadsheet/BI tools use), so
     * gridlines land on round numbers like 5/10/15 rather than an
     * arbitrary value like 14. Used by dashboard.php's bar and line
     * charts; a $max of 0 (an all-empty chart) still returns a small
     * positive ceiling so the chart has *some* scale to draw against
     * rather than dividing by zero.
     */
    public static function niceCeil(int $max, int $targetTicks = 4): int
    {
        if ($max <= 0) {
            return $targetTicks;
        }

        $roughStep = $max / $targetTicks;
        $magnitude = 10 ** floor(log10($roughStep));
        $residual = $roughStep / $magnitude;

        if ($residual > 5) {
            $niceStep = 10 * $magnitude;
        } elseif ($residual > 2) {
            $niceStep = 5 * $magnitude;
        } elseif ($residual > 1) {
            $niceStep = 2 * $magnitude;
        } else {
            $niceStep = $magnitude;
        }

        return (int)(ceil($max / $niceStep) * $niceStep);
    }

    /**
     * EPSS probability (0..1) as a whole-number percentage for display.
     * Rounds to nearest rather than up: most scores are a fraction of a
     * percent, and ceil() would show them all as 1%, overstating them and
     * flattening the differences between them. Anything under 1% shows as
     * "<1%" so "scored, but very unlikely" still reads differently from the
     * caller's own "not scored" marker. Display only - risk scoring and
     * filters use the raw value. Returns plain text; escape it for HTML.
     */
    public static function epssPercent(float $epss): string
    {
        $pct = $epss * 100;
        if ($pct < 1) {
            return '<1%';
        }
        return (int)min(100, round($pct)) . '%';
    }

    /**
     * Hover text for an epssPercent() value: the exact percentage to two
     * places, so a "<1%" can be told apart (0.04% vs 0.9%) and a rounded
     * "10%" that's really 9.7% shows why it missed the 10% risk multiplier.
     * A non-zero score too small for two places shows as "<0.01%" rather
     * than a misleading "0.00%". Plain text; escape it for HTML.
     */
    public static function epssTooltip(float $epss): string
    {
        $pct = $epss * 100;
        $exact = ($pct > 0 && $pct < 0.005) ? '<0.01%' : number_format($pct, 2) . '%';
        return $exact . ' chance of exploitation in the next 30 days (FIRST EPSS)';
    }
}
