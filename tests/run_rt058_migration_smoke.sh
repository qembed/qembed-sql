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
schema_path="${TMPDIR:-/tmp}/qembed_pre_rt058_schema.sql"
git show "$base_schema_commit:qembed_m0_v2_3_3_clean_schema.sql" > "$schema_path"

$P -f "$schema_path"
$P -f ../tests/qembed_context_verify_transaction_setup.sql
$P -f ../tests/qsa003_signed_context_seed.sql
$P -f ../migrations/rt050_signed_context_rls.sql
$P -f ../migrations/rt058_principal_delegation_public_invocation.sql
$P -f ../migrations/rt059_anonymous_context_v2.sql
$P -f ../migrations/rt060_anonymous_object_caller.sql

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
check "qctx2 Anonymous accessors are installed" \
  "SELECT to_regprocedure('qembed_crypto.current_subject_kind()') IS NOT NULL AND to_regprocedure('qembed_crypto.current_object_id()') IS NOT NULL AND to_regprocedure('qembed_crypto.current_anonymous_fingerprint()') IS NOT NULL"
check "Object-scoped Anonymous Caller resolver is installed" \
  "SELECT to_regclass('public.object_anonymous_callers') IS NOT NULL AND to_regprocedure('qembed_crypto.get_or_create_anonymous_caller(uuid,uuid)') IS NOT NULL AND to_regprocedure('qembed_crypto.resolve_anonymous_caller(uuid,uuid,uuid)') IS NOT NULL"

docker cp qembed_context_verify_transaction_probe.py qembed-postgres:/tmp/qembed_context_verify_transaction_probe.py
docker exec --user postgres qembed-postgres bash -euxc \
  "PGDATABASE='${DB}' QSA003_FULL_SCHEMA=1 QSA003_KEEP_SCHEMA=1 /tmp/issuer-venv/bin/python /tmp/qembed_context_verify_transaction_probe.py"

echo "RT-058/RT-059 incremental migration smoke passed"
