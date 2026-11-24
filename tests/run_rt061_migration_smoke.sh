#!/usr/bin/env bash
# Apply the RT-061 Runtime erasure/replay migration and exercise its narrow
# qembed_restore capability against a clean canonical database.
set -euo pipefail
cd "$(dirname "$0")"

DB=${DB:-qembed_rt061_migration}
psql -X -q -d postgres -c "DROP DATABASE IF EXISTS ${DB}" -c "CREATE DATABASE ${DB}"
P="psql -X -q -v ON_ERROR_STOP=1 -d ${DB}"

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
$P -f ../migrations/rt061_runtime_caller_erasure.sql
$P -f ../migrations/rt061b_verified_caller_erasure.sql
$P -f ../migrations/rt061c_cancelled_tool_execution_erasure.sql
$P -f ../tests/rt061_caller_erasure.sql

echo "RT-061 Runtime erasure and restore replay smoke passed"
