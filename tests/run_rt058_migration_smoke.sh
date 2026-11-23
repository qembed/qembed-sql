#!/usr/bin/env bash
# Apply the RT-058 incremental migration to a clean canonical schema.
set -euo pipefail
cd "$(dirname "$0")"

DB=${DB:-qembed_rt058_migration}
psql -X -q -d postgres -c "DROP DATABASE IF EXISTS ${DB}" -c "CREATE DATABASE ${DB}"
P="psql -X -q -v ON_ERROR_STOP=1 -d ${DB}"

# RT-058 is an incremental upgrade. Start from the clean schema immediately
# before PR #78, not the current clean-install schema which already includes it.
base_schema_commit=95ec64a7bd6f687f637144356f03c06b41423941
git fetch --quiet --depth 1 origin "$base_schema_commit"
git show "$base_schema_commit:qembed_m0_v2_3_3_clean_schema.sql" > "$TMPDIR/qembed_pre_rt058_schema.sql"

$P -f "$TMPDIR/qembed_pre_rt058_schema.sql"
$P -f ../tests/qembed_context_verify_transaction_setup.sql
$P -f ../tests/qsa003_signed_context_seed.sql
$P -f ../migrations/rt050_signed_context_rls.sql
$P -f ../migrations/rt058_principal_delegation_public_invocation.sql

check() {
  local label="$1"
  local sql="$2"
  local result
  result="$($P -Atc "$sql")"
  if [[ "$result" != "t" ]]; then
    echo "RT-058 migration smoke failed: $label (got: $result)" >&2
    exit 1
  fi
}

check "Object Anonymous invocation defaults to enabled" \
  "SELECT column_default LIKE '%true%' AND is_nullable='NO' FROM information_schema.columns WHERE table_schema='public' AND table_name='objects' AND column_name='anonymous_invocation_enabled'"
check "delegation revocation actor pair constraint exists" \
  "SELECT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='principal_caller_delegations'::regclass AND conname='principal_caller_delegations_revocation_pair_check' AND contype='c')"
check "Owner identity collision guard is installed" \
  "SELECT pg_get_functiondef('sync_legacy_owner_principal()'::regprocedure) LIKE '%legacy Owner identity conflicts with canonical Principal identity%'"

echo "RT-058 incremental migration smoke passed"
