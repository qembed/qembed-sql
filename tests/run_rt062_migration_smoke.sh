#!/usr/bin/env bash
# Upgrade the canonical worker reservation sweeper to a deterministic cutoff.
set -euo pipefail
cd "$(dirname "$0")"

DB=${DB:-qembed_rt062_migration}
psql -X -q -d postgres -c "DROP DATABASE IF EXISTS ${DB}" -c "CREATE DATABASE ${DB}"
P="psql -X -q -v ON_ERROR_STOP=1 -d ${DB}"

base_schema_commit=95ec64a7bd6f687f637144356f03c06b41423941
git fetch --quiet --depth 1 origin "$base_schema_commit"
schema_path="${TMPDIR:-/tmp}/qembed_pre_rt062_schema.sql"
git show "$base_schema_commit:qembed_m0_v2_3_3_clean_schema.sql" > "$schema_path"

$P -f "$schema_path"
$P -f ../migrations/rt062_deterministic_reservation_sweeper.sql

check() {
  local label="$1"
  local sql="$2"
  local result
  result="$($P -Atc "$sql")"
  if [[ "$result" != "t" ]]; then
    echo "RT-062 migration smoke failed: $label (got: $result)" >&2
    exit 1
  fi
}

check "old one-argument function is removed" \
  "SELECT to_regprocedure('public.sweep_expired_reservations(integer)') IS NULL"
check "two-argument function with deterministic cutoff exists" \
  "SELECT to_regprocedure('public.sweep_expired_reservations(integer,timestamp with time zone)') IS NOT NULL"
check "worker alone can execute reservation sweep" \
  "SELECT has_function_privilege('qembed_worker','public.sweep_expired_reservations(integer,timestamp with time zone)','EXECUTE') AND NOT has_function_privilege('qembed_runtime','public.sweep_expired_reservations(integer,timestamp with time zone)','EXECUTE')"
check "one-argument call remains compatible through the default cutoff" \
  "SELECT sweep_expired_reservations(10) = 0"
check "explicit cutoff call is available to worker" \
  "SELECT sweep_expired_reservations(10, '2026-01-03 00:00:00+00'::timestamptz) = 0"

for invalid_batch in "0" "501" "NULL"; do
  if $P -c "SELECT sweep_expired_reservations(${invalid_batch})" >/dev/null 2>&1; then
    echo "RT-062 migration smoke failed: invalid batch size ${invalid_batch} was accepted" >&2
    exit 1
  fi
done

echo "RT-062 deterministic reservation sweeper migration smoke passed"
