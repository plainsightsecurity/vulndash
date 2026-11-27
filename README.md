# Vulnerability Management Dashboard

A LAMP-stack (Apache/MySQL-MariaDB/PHP) application for
`https://dashboard.plainsightsecurity.co.uk` that will consume vulnerability
data from Qualys and present it to scoped user accounts, filterable by
severity and by Cyber Essentials Plus (CE+) pass/fail status.

## Current status

**The interface, database, and account/tag-scoping logic are built and
tested end-to-end against sample data. The Qualys integration itself is not
implemented yet**, because there's no API access/credentials to build or
test against. This was the deliberate starting point agreed for this first
pass. See "Next steps" at the bottom for exactly what's left.

Everything described below has been run and verified in a disposable test
environment (a fresh MariaDB database, PHP's built-in server, real HTTP
requests): login, lockout-on-repeated-failure, CSRF rejection, tag-scoped
data isolation between accounts, the severity and CE+ filters, pagination,
the account-creation CLI script, and the full two-factor authentication
flow (enroll, confirm, login challenge, trust-device bypass, admin
revoke/reset, self-service disable, MFA lockout) against real generated
TOTP codes verified against the RFC 6238 published test vectors. It has
**not** been run on your actual server/Apache/PHP-FPM setup, so still
treat first deployment as a test deployment.

## What's built vs. what's a stub

| Area | Status |
|---|---|
| Database schema | Complete |
| Login, sessions, lockout | Complete |
| Two-factor authentication (TOTP) + trusted devices | Complete |
| Tag-scoped accounts (multi-tenant style access) | Complete |
| Dashboard (asset count + severity counts) | Complete |
| CE+ pass/fail logic and filter | Complete |
| Vulnerability list, severity filter, pagination | Complete |
| Admin UI: create users, assign/edit tags, reset passwords, activate/deactivate | Complete |
| Account creation (CLI, still available as an alternative to the admin UI) | Complete |
| Qualys KnowledgeBase sync | **Stub only** - throws until implemented |
| Qualys host detection sync | **Stub only** - throws until implemented |
| Qualys asset tag sync | **Not started** - see "Next steps" |

## Directory structure

```
dashboard.plainsightsecurity.co.uk/
├── public/                  <- Apache DocumentRoot points HERE, not at the project root
│   ├── index.php             redirects to /login.php or /dashboard.php
│   ├── login.php
│   ├── logout.php
│   ├── mfa.php                self-service two-factor setup/manage (enable, disable, trusted devices)
│   ├── mfa_verify.php         login-time two-factor code challenge
│   ├── dashboard.php         top-level asset/severity/CE+ counts
│   ├── vulnerabilities.php   filterable, paginated vulnerability list
│   ├── admin/
│   │   └── users.php         admin-only: create users, assign tags, reset passwords, manage MFA
│   ├── .htaccess
│   └── assets/{css,js}        includes assets/js/qrcode.js (vendored, MIT-licensed, for MFA QR codes)
├── src/                     <- outside the web root
│   ├── bootstrap.php         autoloading + session setup, included by every entry point
│   ├── config/config.php     DB + Qualys credentials + MFA encryption key (edit before deploying)
│   ├── Lib/                  Config, Database, Auth, Helpers, CvssCalculator,
│   │                         VulnerabilityRepository, UserRepository, Totp,
│   │                         MfaService, TrustedDeviceRepository
│   └── views/                header.php / footer.php
├── scripts/                 <- CLI-only, outside the web root
│   ├── create_account.php    creates a user + assigns tag scope
│   ├── sync_knowledge_base.php    cron job (stub - see status table)
│   ├── sync_host_detections.php   cron job (stub - see status table)
│   └── lib/QualysApiClient.php    the integration point for both syncs
├── database/
│   ├── schema.sql
│   ├── seed_sample_data.sql  optional - sample data for testing the UI now
│   └── migrations/           schema changes for installs deployed before a given fix
└── config/
    ├── apache-vhost.conf            final vhost - only enable once a cert exists (see below)
    └── apache-vhost-bootstrap.conf  temporary port-80-only vhost, used to obtain the first cert
```

`public/` is the only folder that should ever be reachable over HTTP.
Config, source, scripts, and SQL all live outside it deliberately, and the
provided vhost config denies them explicitly as a second layer of
protection in case `DocumentRoot` is ever pointed at the wrong place.

## Updating the live server

The code lives in the private GitHub repo `plainsightsecurity/vulndash`, and
the live install at `/var/www/dashboard.plainsightsecurity.co.uk` is a git
working copy of `main`, owned by `www-data`. Changes are committed straight
to `main` (no pull requests); nothing reaches production until it is pulled
on the server.

**Pulling changes onto the server:**

```
deploy-dashboard
```

`/usr/local/bin/deploy-dashboard` runs `git pull --ff-only` as `www-data`,
prints the new commit and the files changed, and lists any newly added
files under `database/migrations/`. Apply those with the migration runner,
which knows which ones this database has already had:

```
sudo php /var/www/dashboard.plainsightsecurity.co.uk/scripts/migrate.php --root            # what's pending
sudo php /var/www/dashboard.plainsightsecurity.co.uk/scripts/migrate.php --root --confirm  # apply it
```

`--root` connects as MySQL root over the local socket (as
`sudo mysql vulndash` does); without it the runner uses the `db.*`
credentials in `src/config/config.php`. It applies pending files in filename
order, records each one in `schema_migrations` once it succeeds, stops at the
first failure with the MySQL error, and flags any applied file that has been
edited since (`CHANGED` - re-run it deliberately with `--rerun=<file>
--confirm`). See the docblock in `scripts/migrate.php` for every option.
First use on an existing database: `--baseline --confirm` records every
current migration as applied without running anything.
Crontab and `src/config/config.php` changes are still manual; the commit
message says when one is needed.

**Committing an edit made on the server:**

```
save-dashboard "What changed"
```

`/usr/local/bin/save-dashboard` commits everything outstanding, rebases on
anything pushed since (`git pull --rebase`) and pushes. Run it straight
after any server-side edit: an uncommitted edit, or a local commit that
hasn't been pushed, makes the next `deploy-dashboard` refuse to pull.

**Rolling back** to the previous version if a deploy misbehaves:

```
sudo -u www-data git -C /var/www/dashboard.plainsightsecurity.co.uk log --oneline -5
sudo -u www-data git -C /var/www/dashboard.plainsightsecurity.co.uk reset --hard <commit>
```

Then revert the bad commit in the repo, or the next `deploy-dashboard`
will pull it straight back in.

**Never in git:** `src/config/config.php` (credentials - see
`src/config/config.example.php` for every setting) and anything matched
by `.gitignore` (logs, zips, backups). The server pulls and pushes over
SSH with its own deploy key (`/var/www/.ssh/github_dashboard`, host alias
`github-dashboard` in `/var/www/.ssh/config`); `main` is protected
against force-pushes and deletion.

## Tests

`tests/run.sh` runs the whole suite against a disposable MySQL database
called `vulndash_test`:

- **PHP syntax** - every `.php` file through `php -l`.
- **Schema and migrations** - `install_schema.sql` loads on a fresh MySQL
  8.0, and applying every file in `database/migrations/` on top of it with
  `scripts/migrate.php --confirm` succeeds and changes nothing (so the
  migrations are safe to re-run and `install_schema.sql` already includes
  them), after which the runner reports nothing pending.
- **Unit and integration tests** (`tests/cases/*Test.php`) - CE+ scoring,
  tenant isolation, KEV/EPSS/CE+ filters and the PDF, scan-request
  cooldowns, the missing-KB-QID queue, and live account checks.
- **Page smoke tests** (`tests/pages.php`) - every page rendered as an
  admin and as a client with no PHP warnings or errors, admin pages
  refusing a client, and nothing from another tenant (or an untagged
  asset) appearing in a client's pages or exports.

It runs automatically on every push to GitHub (`.github/workflows/tests.yml`,
MySQL 8.0 + PHP 8.3). The tick or cross next to each commit on GitHub is
the signal: don't run `deploy-dashboard` on a red cross.

Tests never touch `src/config/config.php` or the live database: `run.sh`
sets `VULNDASH_CONFIG` so `Config` loads `tests/config.test.php` instead,
which only ever names `vulndash_test` and points Qualys at a closed port.
To run them on a server, give them a MySQL user limited to that database:

```
sudo mysql -e "CREATE USER 'vulndash_test'@'127.0.0.1' IDENTIFIED BY 'choose-one';
               GRANT ALL ON vulndash_test.* TO 'vulndash_test'@'127.0.0.1';"
DB_USER=vulndash_test DB_PASS=choose-one tests/run.sh
```

New tests: add a `tests/cases/<Thing>Test.php` calling
`test('what it checks', function () { ... })` with `eq()` / `ok()`;
each test starts from an empty database, and `seed_estate()` in
`tests/lib.php` loads the standard two-tenant sample data.

## Deploying (first install)

1. **Clone the repo** to `/var/www/dashboard.plainsightsecurity.co.uk/`
   (or adjust the paths in `config/apache-vhost.conf` if you use a
   different location). The deploy key and SSH alias described above
   have to exist first.

   ```
   sudo mkdir /var/www/dashboard.plainsightsecurity.co.uk
   sudo chown www-data:www-data /var/www/dashboard.plainsightsecurity.co.uk
   sudo -u www-data git clone git@github-dashboard:plainsightsecurity/vulndash.git /var/www/dashboard.plainsightsecurity.co.uk
   ```

2. **Install packages** (Ubuntu):

   ```
   sudo apt update
   sudo apt install apache2 mysql-server php php-mysql php-curl
   sudo a2enmod ssl headers rewrite
   ```

3. **Create the database and app user:**

   ```
   sudo mysql -u root -e "CREATE DATABASE vulndash CHARACTER SET utf8mb4;"
   sudo mysql -u root -e "CREATE USER 'vulndash_app'@'127.0.0.1' IDENTIFIED BY 'choose-a-strong-password';"
   sudo mysql -u root -e "GRANT ALL PRIVILEGES ON vulndash.* TO 'vulndash_app'@'127.0.0.1'; FLUSH PRIVILEGES;"
   mysql -u root vulndash < install_schema.sql
   ```

   `install_schema.sql` is the authoritative schema (a `mysqldump
   --no-data` of production); `database/schema.sql` is older and has
   drifted, so don't use it for a new install.

   Optionally load sample data so you can see the interface working before
   Qualys access exists (see "Test accounts" below):

   ```
   mysql -u root vulndash < database/seed_sample_data.sql
   ```

   `install_schema.sql` already includes every migration in
   `database/migrations/`, so a new install doesn't need to run them -
   record them as applied instead, so later ones are picked up correctly:

   ```
   sudo php scripts/migrate.php --root --baseline --confirm
   ```

   After that, `scripts/migrate.php` applies new migrations as they arrive
   (see "Updating the live server" above).

4. **Create `src/config/config.php`** from the example, then fill in the
   database password, Qualys credentials and Resend key:

   ```
   sudo -u www-data cp src/config/config.example.php src/config/config.php
   sudo chmod 640 src/config/config.php
   ```

   Also generate a key for
   `security.mfa_encryption_key` (used to encrypt TOTP secrets at rest -
   see "Two-factor authentication (MFA)" below) with:

   ```
   openssl rand -base64 32
   ```

5. **Get a TLS certificate and enable the site.** This has to happen in two
   phases, because `config/apache-vhost.conf` already has a `:443` block
   with `SSLCertificateFile`/`SSLCertificateKeyFile` paths in it - and
   Apache refuses to start or reload with *any* enabled vhost that points
   at certificate files that don't exist yet. That failure isn't scoped to
   just this site either: `apache2ctl configtest` failing means Apache
   won't (re)start at all until it's fixed, which is what
   `certbot --apache` runs into if you hand it the full vhost before a
   certificate exists.

   **Phase 1 - bootstrap with the port-80-only vhost and get the
   certificate:**

   ```
   sudo apt install certbot python3-certbot-apache
   sudo cp config/apache-vhost-bootstrap.conf /etc/apache2/sites-available/dashboard.plainsightsecurity.co.uk.conf
   sudo a2ensite dashboard.plainsightsecurity.co.uk
   sudo apache2ctl configtest        # should print "Syntax OK"
   sudo systemctl reload apache2

   sudo certbot certonly --apache -d dashboard.plainsightsecurity.co.uk
   ```

   `certonly` matters here - it tells certbot to only obtain and place the
   certificate files, not to rewrite the Apache config itself, so the vhost
   below stays authoritative rather than fighting a certbot-generated one.

   **Phase 2 - swap in the full vhost now that the certificate exists:**

   ```
   sudo cp config/apache-vhost.conf /etc/apache2/sites-available/dashboard.plainsightsecurity.co.uk.conf
   sudo apache2ctl configtest        # should print "Syntax OK" now
   sudo systemctl reload apache2
   ```

   Confirm auto-renewal will work before moving on:

   ```
   sudo certbot renew --dry-run
   ```

   If you already hit the `apache2ctl configtest` / `SSLCertificateFile...
   does not exist` error by running `certbot --apache` against the full
   vhost directly, just run Phase 1 above to get Apache back into a valid
   state (the bootstrap vhost has no certificate paths for it to fail on),
   then continue with the `certonly` command and Phase 2.

6. **Create your real accounts** and remove the sample ones (see below).

## Test accounts (sample data only - remove before going live)

If you loaded `seed_sample_data.sql`, two accounts exist, both with password
`ChangeMe123!`:

- `admin` - `is_admin = 1`, sees every asset/vulnerability
- `acme_client` - scoped to the "Acme Corp - Production" tag only, so you can
  see the tag-scoping working (it won't see the "Beacon Retail" or
  "Plainsight - Internal" sample assets)

Delete these (and the sample tags/assets/detections) once you've had a look,
or before this is reachable from anywhere untrusted:

```sql
DELETE FROM users WHERE username IN ('admin', 'acme_client');
-- and, if you don't want the sample assets/vulns either:
TRUNCATE TABLE host_detections;
DELETE FROM assets;
DELETE FROM tags;
DELETE FROM knowledge_base;
```

## Creating real accounts

Log in as an admin and go to **Manage Users** (`/admin/users.php`) to:

- create new accounts and assign which tags they can see
- edit an existing account's tags
- promote/demote admin status
- reset a password
- activate/deactivate an account
- delete an account
- add tags manually (useful now, before the Qualys tag sync exists - see
  the "Tags" section on that same page)

A few things worth knowing about how it behaves:

- **Tags are Qualys asset tags (or Activation IDs - see below)**, not
  arbitrary labels - each one has both a local display name and the actual
  Qualys identifier it corresponds to (numeric tag ID, tag name, or
  Activation ID UUID - whichever your subscription uses; that column is a
  plain string, not a number, precisely so any of these fit). A non-admin
  account with no tags assigned sees zero data (fails closed), and the
  "create user"/"edit tags" forms warn you before letting that happen
  accidentally.
- **You can't demote, deactivate, or delete your own account** from this
  page, so you can't lock yourself out.
- Deleting a user is immediate and permanent (their `user_tags`
  assignments cascade-delete with them); deactivating is reversible and
  is usually what you want for someone leaving temporarily.
- **Agent activation ID** (Tags table, `tags.agent_activation_id`): set a
  tag's Cloud Agent activation ID and every account that can see the tag
  gets an **Install agent** button on the Assets page while that tag is
  selected in the Tags filter (not on the all-tags view). It opens an
  overlay with the Windows (PowerShell) and macOS/Linux install one-liners,
  the same ones as the CE+ onboarding instructions, with the ID filled in
  and a Copy button for each. Blank = no install command for that tag. Only UUIDs are
  accepted, since the ID ends up in a command run as administrator. The
  command text lives in `src/Lib/AgentInstall.php`. This is separate from
  the Qualys identifier column, which is what links the tag to Qualys data.

The CLI script from earlier is still there as an alternative if you'd
rather script account creation (e.g. bulk-provisioning) than click through
the UI:

```
php scripts/create_account.php --username=jsmith --email=jsmith@client.com --tags=1001,2002
php scripts/create_account.php --username=admin2 --email=admin2@plainsightsecurity.co.uk --admin
```

`--tags` there takes **Qualys** identifiers (numeric tag ID, tag name, or
Activation ID), not local database IDs, same as the web UI - the tag has
to already exist locally (via the admin UI's "Tags" section, or a future
tag sync) or it's skipped with a warning.

## Two-factor authentication (MFA)

TOTP-based (Google Authenticator, Authy, 1Password, etc) two-factor
authentication, opt-in per account:

- **Every account (admin or client) can turn it on themselves** at
  `/mfa.php` (linked as "Security" in the nav once logged in) - scan the
  QR code or enter the key manually, confirm with a code, done. No
  account is forced into it by this change; if you want to require MFA
  for everyone, or just for admins, that's a small, deliberate follow-up
  rather than something this change assumes for you.
- **"Trust this device" at the code-entry step during login** skips the
  code for 30 days on that browser - the password is always still
  required either way, this only ever skips the second factor. Both the
  account owner (from `/mfa.php`) and any admin (from Manage Users) can
  see and revoke trusted devices individually, or all at once.
- **Admin recovery for a lost device:** Manage Users has a "Reset MFA"
  action per account (under "Manage MFA") that fully disables MFA and
  clears the secret, so the person can re-enroll from scratch. Also
  revokes any trusted devices on that account at the same time, since
  there's no second factor left for a "skip the second factor" grant to
  mean anything.
- **Rate-limited separately from password attempts:** 5 wrong codes locks
  MFA verification for 15 minutes on that account, independent of the
  password lockout in `src/Lib/Auth.php` - a 6-digit code has a much
  smaller keyspace than a password, so it needs its own tighter limit.
- **Secrets are encrypted at rest** (AES-256-GCM) using
  `security.mfa_encryption_key` in `src/config/config.php` - see that
  file's comments for how to generate one. This is required before
  anyone can enable MFA; the app fails closed with a clear message
  rather than ever storing a secret in plaintext if it's missing.
  **Changing this key after accounts have enrolled makes their stored
  secrets undecryptable** - treat it like the database password (set
  once, back it up, keep it in your secrets store), and use "Reset MFA"
  to recover an account if it ever does change.
- No backup/recovery codes are implemented - "Reset MFA" from the admin
  side is the account-recovery path instead. Worth a follow-up if
  self-service recovery (without needing an admin) matters to you.
- **Architectural open question, same spirit as the tag-scoping one
  below:** whether MFA should eventually be mandatory (for everyone, or
  just admins) isn't decided here - this ships it as available and
  opt-in, and enforcing it is a separate, deliberate decision for later.

## Key design decisions and assumptions

Worth checking these match what you had in mind, since a few things weren't
fully pinned down in the brief:

- **No PHP framework.** Plain PHP with PDO, a five-line autoloader, and no
  Composer/vendor directory - so deployment really is "copy the files over".
  Straightforward to port to Laravel/Symfony later if you'd rather.
- **CVSS scoring precedence** exactly as specified: CVSS3 base score, else
  CVSS2 base score, else an estimate from the Qualys severity level. Only
  the High (7.0-8.9) and Critical (9.0-10.0) bands were specified, since
  those are the only ones that can cross the CE+ threshold of 7.0.
  Informational/Low/Medium bands are this codebase's own extension (using
  the standard NVD CVSS v3 qualitative ranges) so every vulnerability still
  gets *some* displayable score - see the comments in
  `src/Lib/CvssCalculator.php` if you want to change those.
- **Dashboard counts and the vulnerability list show open findings only**
  (`status != 'Fixed'`) - fixed vulnerabilities are excluded rather than
  counted historically. Easy to change in `src/Lib/VulnerabilityRepository.php`
  if you'd rather see lifetime totals.
- **The severity counts (Critical/High/Medium/Low/Informational) use
  Qualys's own severity level**, not the derived CVSS score. The CE+ filter
  is the only place the derived/estimated CVSS score is used for filtering,
  matching the brief ("CE+ failures... CVSS base score of 7 or above").
- **Tag scoping fails closed:** a non-admin account with no tags assigned
  sees zero assets/vulnerabilities, rather than accidentally seeing
  everything. Deliberate, given this handles security data for what looks
  like multiple separate clients. The admin UI enforces the same rule when
  creating/editing accounts - it won't let you save a non-admin account
  with zero tags without at least warning you first.
- **The admin UI stops you from locking yourself out:** an admin can't
  demote, deactivate, or delete their own account from `/admin/users.php`.
  Use a second admin account (or the CLI script) if you genuinely need to
  do that.
- **The visual design** is a dark, information-dense "operations console"
  style (IBM Plex Sans/Mono, a graduated slate→amber→ember severity scale
  instead of literal traffic-light colours, and a coloured left-edge stripe
  per table row for at-a-glance triage) rather than a generic admin-template
  look, since this is a tool analysts will use daily, not a marketing page.

## Cron jobs (once Qualys API access exists)

Both sync scripts currently throw a clear "not implemented" error - see the
"Next steps" section. Once `scripts/lib/QualysApiClient.php` is filled in,
suggested cron entries are:

```cron
# KnowledgeBase - changes slowly, sync every few hours is plenty
0 */4 * * * php /var/www/dashboard.plainsightsecurity.co.uk/scripts/sync_knowledge_base.php >> /var/log/vulndash/kb_sync.log 2>&1

# Host detections - match this to your actual Qualys scan cadence
0 * * * * php /var/www/dashboard.plainsightsecurity.co.uk/scripts/sync_host_detections.php >> /var/log/vulndash/detection_sync.log 2>&1
```

Create the log directory first: `sudo mkdir -p /var/log/vulndash && sudo chown www-data:www-data /var/log/vulndash`.
Every run is recorded in the `sync_log` table (status, records processed,
error message) regardless of cron - useful for a simple "last sync" widget
later if you want one. The dashboard's sync-status strip flags a sync as
"overdue" only after roughly **twice** its expected interval without a success
(KB defaults to a 4-hour expected interval, so ~8 hours of slack; host
detections 20 minutes). If the crontab cadence changes, update the matching
`sync.knowledge_base_expected_interval_minutes` /
`sync.host_detections_expected_interval_minutes` in `src/config/config.php`
(or the defaults in `src/Lib/SyncStatusRepository.php`) so the strip stays
accurate.

**New-KEV alert emails.** `scripts/send_kev_alerts.php` emails an account
when a vulnerability on the CISA Known Exploited Vulnerabilities list newly
appears in its scope (a new detection of a KEV-listed QID, or CISA adding an
existing finding's CVE). One email per run however many are new; the email
has no vulnerability detail, only a link to `/vulnerabilities?kev=1`. On by
default per account, switchable under Preferences (`users.kev_alerts`). The
first run for an account records its existing KEV findings silently, so
there is no backlog email. Needs
`database/migrations/2026-11-add-kev-alerts.sql`. Makes no Qualys API calls.

```cron
55 * * * * php /var/www/dashboard.plainsightsecurity.co.uk/scripts/send_kev_alerts.php >> /var/log/vulndash/kev_alerts.log 2>&1
```

`--dry-run` shows who would be emailed without sending or recording anything.

**Audit log.** Admin menu > Audit Log (`/admin/audit_log`) lists who did
what: sign-ins (and failures, lockouts, rejected two-factor codes), account
security changes, every admin action on users and tags, hidden findings,
scan and agent-uninstall requests, custom remediation edits, CE+
assessment dates and report exports - with the user, target, details and IP
address. Filter by user, activity, date or text; download as CSV. Written by
`src/Lib/AuditLog.php` (best-effort: a failed audit write never blocks the
action), needs `database/migrations/2026-11-add-audit-log.sql`, and prunes
itself after `audit.retention_days` (default 365) - no cron job. Actions by
CLI scripts and cron jobs aren't recorded.

**Agent Setup.** Admin menu > Agent Setup (`/admin/agent_setup`) creates a
client organisation's Qualys tag and activation key: a static, top-level tag
(suggested as `<Organisation-Name>-Agents`, letters/numbers/hyphens only,
editable) and an UNLIMITED key with the same title that applies it. The
tag's local row gets the key's activation ID and is added to the
organisation, so its members get the Install agent button. One tag and key
per client: a same-named tag in Qualys (any case) stops the set-up for the
admin to use it (static and unclaimed only) or pick another name; a
same-titled key stops it too. Each Qualys id is saved as soon as it's
returned, so Retry resumes without making a second tag or key. An
organisation that already has a tag with an activation ID gets Link existing
(one key search to confirm the key applies the tag; creates nothing) in place
of Create. Delete removes any set-up, linked ones included - key and tag in
Qualys and the local tag - after the tag name is typed exactly (checked
server-side before any Qualys call), so a name can be tested and reused;
Unlink forgets the record only. Deleting an organisation deletes its set-up
record. Calls Qualys
during the request (about four calls, each on its own 25-per-24h counter,
logged on API Usage) with the same API user as the syncs, which needs Create
User Tag and Create Activation Key (plus Delete User Tag and Delete
Activation Key to use Delete). Keys are licensed for
`qualys.activation_key_modules` (default `['VM_LICENSE']`). Logic in
`src/Lib/AgentProvisioner.php`; needs
`database/migrations/2026-11-add-agent-provisioning.sql` (diagnostic:
`scripts/diagnose_agent_provisioning_migration.php`, `--check-qualys` to
confirm read access). No cron job.

**History retention.** `scripts/prune_history.php` trims the history tables
that nothing else prunes: `qualys_api_call_log`, `sync_log`, sent/failed rows
in `scan_request_queue`, and the daily posture snapshots in
`asset_vuln_snapshot`. Defaults are 90 days for the first three and 400 days
for snapshots (enough for a year-on-year comparison), set under `retention` in
`src/config/config.php`. Each has a minimum it won't go below (30 / 7 / 7 / 90
days) so the API Usage page and Trends always have their data, and the newest
run and newest successful run of each sync are kept whatever their age, since
the host and KB syncs take their incremental starting point from the last
success. Pending scan requests are never touched. Deletes run in batches of
5,000. Makes no Qualys API calls. `--dry-run` reports what would go.

```cron
20 3 * * * php /var/www/dashboard.plainsightsecurity.co.uk/scripts/prune_history.php >> /var/log/vulndash/prune_history.log 2>&1
```

**New-QID fast-path.** Each steady-state KB run (after the historical backfill
completes) makes one extra id-range call - `id_min = (highest local QID) + 1` -
to pick up brand-new QIDs immediately, without waiting for Qualys to index
their `last_modified` date (the same indexing lag the trailing overlap absorbs
for *modified* QIDs). Because Qualys assigns QIDs in increasing numeric order,
a new QID is always above the local maximum, so this catches it for the cost of
a single call. It complements, and does **not** replace,
`scripts/reconcile_kb_by_id.php`, which remains the exhaustive backstop that
walks the whole QID space to catch a gap anywhere (including below the local
max). Optional config (both have safe defaults, so no change is required):

```php
    'qualys' => [
        // ...existing keys...
        'kb_new_qid_fastpath_enabled' => true,     // set false to disable the extra call
        'kb_new_qid_fastpath_span'    => 1000000,  // how far above the local max to scan
    ],
```

**Resolved / remediation tracking.** On this agent-only platform a vulnerability
is remediated by the Cloud Agent simply no longer reporting its QID, at which
point `sync_host_detections.php` deletes the local detection (it never becomes a
`status='Fixed'` row, and Qualys isn't asked for Fixed detections). The posture
trend line (`asset_vuln_snapshot`, a daily open count) reflects that drop
correctly, but the Trends "Resolved" movement figure used to read from
`status='Fixed'` rows that never exist here, so it was always 0. Each deletion
now writes a small tombstone to `detection_resolutions` (`asset_id`, `qid`,
`resolved_at`), and `getMovementCounts()` counts "Resolved" from those, tag-scoped,
within its window. The table is append-only and **pruned on every sync run**, so
it reaches a small steady state rather than growing:

```php
    'sync' => [
        // ...existing keys...
        'resolution_retention_days' => 90,  // tombstones older than this are pruned each run
    ],
```

Default retention is 90 days - three times the 30-day movement window nothing
reads past. Deploy prerequisite (run once, after the core schema):

```bash
mysql -u root -p vulndash < database/migrations/2026-07-add-detection-resolutions.sql
```

Preview a prune without deleting anything with
`php scripts/sync_host_detections.php --dry-run-prune` (read-only: reports the
table size, date span, and how many rows the current retention would remove,
then exits without syncing).

The Trends "Recently resolved" list also reads from these tombstones (deduped to
the latest resolution per asset+QID). Because the underlying detection is
deleted, its effective CVSS score is captured onto the tombstone at deletion time
(so the list can show severity) and the title is joined from the still-present
knowledge_base; the resolved title isn't a link, since there's no live detection
page to open. That score column is a second, separate migration - apply it after
the table migration above:

```bash
mysql -u root -p vulndash < database/migrations/2026-07-add-resolution-cvss.sql
```

## Exploitability intelligence (CISA KEV + FIRST EPSS)

On top of the CVSS-derived severity, the dashboard surfaces two real-world
exploitation signals so a client can triage by "is this actually being
exploited" rather than base score alone:

- **CISA KEV** - a CVE on the Known Exploited Vulnerabilities catalogue is
  confirmed exploited in the wild, and carries a federal remediation due date
  and a ransomware-campaign flag. Shown as a red **KEV** chip on the list, top
  vulnerabilities and detail page, a **Known exploited** dashboard stat card,
  a **Known exploited only** list filter (`?kev=1`), and a callout banner on
  the detail page.
- **FIRST EPSS** - a daily 0..1 probability that a CVE will be exploited in the
  next 30 days, plus its percentile. Shown as a sortable **EPSS** column on the
  list and a Scoring-panel row on the detail page, with an **EPSS ≥** list
  filter. Both are added to the CSV export.

Data flow (see `database/migrations/2026-07-add-exploit-intel.sql` and
`src/Lib/ExploitIntelRepository.php`): the two feeds are per-CVE
(`cisa_kev`, `epss_scores`), `kb_cve` normalises `knowledge_base.cve_ids` into
`(qid, cve)` pairs, and `qid_exploit` is a per-QID rollup the dashboard reads
via a single LEFT JOIN with no read-time aggregation (the same caching
philosophy as `effective_cvss_score`). `scripts/sync_exploit_intel.php`
refreshes all of it and is the only writer; it makes **no** Qualys API calls
and does not touch the Qualys rate budget.

Deploy prerequisite (run once, after the core schema):

```bash
mysql -u root -p vulndash < database/migrations/2026-07-add-exploit-intel.sql
```

Suggested cron (as www-data), staggered off the Qualys jobs - four times a day:

```cron
# Exploit intelligence (CISA KEV + FIRST EPSS) - both feeds update at most daily
30 0,6,12,18 * * * php /var/www/dashboard.plainsightsecurity.co.uk/scripts/sync_exploit_intel.php >> /var/log/vulndash/exploit_intel.log 2>&1
```

**Outbound access:** this box must be able to reach the two feed hosts over
HTTPS - by default `www.cisa.gov` and `epss.empiricalsecurity.com` (the same
kind of outbound the Qualys and Resend integrations already need). CISA
rate-limits/blocks some clients; the script sends a descriptive User-Agent and
fails with an actionable message if it's blocked.

**Config (optional).** Every key has a sensible built-in default, so the sync
works with no config change at all. Add an `exploit_intel` block to
`src/config/config.php` only to tune or to repoint at a mirror:

```php
    'exploit_intel' => [
        // Defaults shown; override to point at a mirror if a feed host blocks you.
        'kev_url'  => 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
        'epss_url' => 'https://epss.empiricalsecurity.com/epss_scores-current.csv.gz',
        'user_agent' => 'Plainsight VulnDash exploit-intel sync',
        'http_timeout_sec' => 120,
    ],
```

Operational flags: `--skip-kev` / `--skip-epss` refresh just one feed (the
other's table is left as-is and the rollup still rebuilds); `--kev-file=` /
`--epss-file=` ingest a local file instead of fetching (offline re-ingest or an
air-gapped mirror; the EPSS file may be `.csv` or `.csv.gz`). If only one feed's
fetch fails, the run still succeeds, keeps that feed's previous data, rebuilds
the rollup, and notes the failure in `sync_log.error_message`; it reports
failure only if every attempted feed failed.

## Next steps for Qualys integration

This is the main remaining piece of work, and needs real API access to do
properly rather than guessing further:

1. Confirm your Qualys **API base URL** (varies by platform/shard - check
   Help > About in the Qualys UI) and put it in `src/config/config.php`.
2. Confirm the exact **KnowledgeBase** endpoint/parameters/response shape
   for your subscription and implement `QualysApiClient::fetchKnowledgeBaseChunk()`.
3. Confirm the exact **host detection** endpoint and implement
   `QualysApiClient::fetchHostDetections()`, including pagination and
   incremental sync (only pulling what's changed since the last run).
4. Work out what you're actually scoping users by - a named **Asset Tag**,
   a Cloud Agent **Activation ID**, or a mix depending on the client. This
   determines both the API call (`fetchAssetTags()` almost certainly needs
   the Asset Management API for named tags, but Activation ID mapping may
   come from the Cloud Agent API instead) and whether tag sync is one
   scheduled job or two.
5. Once tags are flowing in, `scripts/create_account.php` and the admin UI
   will resolve against real Qualys identifiers instead of the sample ones -
   no code change needed there, the identifier column already accepts any
   string (see `database/migrations/2026-07-widen-qualys-tag-id.sql` if
   you deployed before that fix).

Everything downstream of the API responses - upserting, CVSS calculation,
CE+ flagging, the dashboard, and the filtered list - is already built and
tested against the shape these scripts expect; it's the three Qualys calls
themselves that are the open item.
