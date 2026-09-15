#!/bin/sh
# An isolated PostgreSQL instance; never points at a running/project database.
set -eu
POSTGRES_BIN=${POSTGRES_BIN:-/opt/homebrew/opt/postgresql@16/bin}
test_root=$(mktemp -d /tmp/pf-service-contract-tests.XXXXXX)
test_repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cleanup() {
  "$POSTGRES_BIN/pg_ctl" -D "$test_root/data" stop -m fast >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM
"$POSTGRES_BIN/initdb" -D "$test_root/data" --auth=trust > "$test_root/init.log"
"$POSTGRES_BIN/pg_ctl" -D "$test_root/data" -l "$test_root/server.log" -o "-h '' -k $test_root" start >/dev/null
"$POSTGRES_BIN/psql" -h "$test_root" -d postgres -v ON_ERROR_STOP=1 \
  -f "$test_repo/tests/fixtures/service-bootstrap.sql" \
  -f "$test_repo/supabase/migrations/0001_identity.sql" \
  -f "$test_repo/supabase/migrations/0002_manifest.sql" \
  -f "$test_repo/supabase/migrations/0003_autoridade.sql" \
  -f "$test_repo/supabase/migrations/20260829012439_registry_identity_authority.sql" \
  -f "$test_repo/tests/fixtures/service-context.sql" \
  -c 'grant usage on schema extensions to authenticated' \
  -f "$test_repo/supabase/migrations/20260915083641_antenna_service_contracts.sql" \
  -f "$test_repo/tests/service-contracts.sql"
printf 'Service contracts and RLS verified; isolated database: %s\n' "$test_root"
