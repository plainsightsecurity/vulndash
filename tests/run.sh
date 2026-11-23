#!/bin/bash
# VulnDash test suite: PHP lint, schema/migration check, unit + integration
# tests and a page smoke test, all against a disposable MySQL database
# called vulndash_test. Never touches src/config/config.php or the live
# vulndash database - see tests/config.test.php.
#
# Usage:  DB_USER=root DB_PASS=secret tests/run.sh
#         (DB_HOST defaults to 127.0.0.1, DB_PORT to 3306)
# Runs automatically on every push via .github/workflows/tests.yml.

set -uo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

export VULNDASH_CONFIG="$ROOT/tests/config.test.php"
export DB_HOST=${DB_HOST:-127.0.0.1} DB_PORT=${DB_PORT:-3306} DB_USER=${DB_USER:-root} DB_PASS=${DB_PASS:-}
export MYSQL_PWD="$DB_PASS"
DB=vulndash_test
MYSQL=(mysql --protocol=TCP -h"$DB_HOST" -P"$DB_PORT" -u"$DB_USER")
DUMP=(mysqldump --protocol=TCP -h"$DB_HOST" -P"$DB_PORT" -u"$DB_USER" --no-data --skip-comments --skip-dump-date --no-tablespaces)
FAILED=()

step() { echo; echo "=== $1 ==="; }

step "PHP syntax"
LINT=$(find . -name '*.php' -not -path './.git/*' -print0 | xargs -0 -n1 -P4 php -l 2>&1 | grep -v '^No syntax errors')
if [ -n "$LINT" ]; then echo "$LINT"; FAILED+=("lint"); else echo "  ok    all files"; fi

step "Schema and migrations"
"${MYSQL[@]}" -e "DROP DATABASE IF EXISTS $DB; CREATE DATABASE $DB CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci" || { echo "  FAIL  cannot create $DB"; exit 1; }
if "${MYSQL[@]}" "$DB" < install_schema.sql; then
    echo "  ok    install_schema.sql loads"
    # Every migration must already be reflected in install_schema.sql and be
    # safe to re-run: applying them all to a fresh install changes nothing.
    "${DUMP[@]}" "$DB" | sed -E 's/ AUTO_INCREMENT=[0-9]+//' > /tmp/vd_schema_before.sql
    MIG_OK=1
    for m in database/migrations/*.sql; do
        if ! "${MYSQL[@]}" "$DB" < "$m" >/dev/null 2>/tmp/vd_mig_err; then
            echo "  FAIL  $m: $(head -c 300 /tmp/vd_mig_err)"; MIG_OK=0
        fi
    done
    "${DUMP[@]}" "$DB" | sed -E 's/ AUTO_INCREMENT=[0-9]+//' > /tmp/vd_schema_after.sql
    if [ $MIG_OK = 1 ] && diff -q /tmp/vd_schema_before.sql /tmp/vd_schema_after.sql >/dev/null; then
        echo "  ok    migrations re-run cleanly and install_schema.sql already includes them"
    else
        [ $MIG_OK = 1 ] && { echo "  FAIL  migrations changed the schema - install_schema.sql is out of date:"; diff /tmp/vd_schema_before.sql /tmp/vd_schema_after.sql | head -40; }
        FAILED+=("migrations")
    fi
else
    echo "  FAIL  install_schema.sql does not load"; FAILED+=("schema")
fi

step "Unit and integration tests"
php tests/run.php || FAILED+=("tests")

step "Page smoke tests"
php tests/pages.php || FAILED+=("pages")

echo
if [ ${#FAILED[@]} -eq 0 ]; then echo "ALL PASSED"; exit 0; fi
echo "FAILED: ${FAILED[*]}"; exit 1
