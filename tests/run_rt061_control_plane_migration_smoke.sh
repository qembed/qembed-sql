#!/usr/bin/env bash
# Validate the dedicated Control-plane tombstone schema and its writer/reader role.
set -euo pipefail
cd "$(dirname "$0")"

DB=${DB:-qembed_rt061_control_plane}
psql -X -q -d postgres -c "DROP DATABASE IF EXISTS ${DB}" -c "CREATE DATABASE ${DB}"
P="psql -X -q -v ON_ERROR_STOP=1 -d ${DB}"

$P -f ../migrations/rt061_control_plane_caller_deletion_ledger.sql
$P -f ../migrations/rt061a_control_plane_tombstone_sequence_lock.sql

psql -X -q -d ${DB} -v ON_ERROR_STOP=1 \
  -c "CREATE ROLE rt061_control_plane_login LOGIN PASSWORD 'rt061-test' IN ROLE qembed_control_plane_runtime"

PGPASSWORD=rt061-test psql -X -q -h 127.0.0.1 -U rt061_control_plane_login -d ${DB} -v ON_ERROR_STOP=1 \
  -c "INSERT INTO qembed_control_plane.caller_deletion_tombstones (tenant_id, caller_hash, key_version) VALUES ('61000000-0000-4000-8000-000000000001', decode(repeat('ab', 32), 'hex'), 'v1')" \
  -c "SELECT 1 FROM qembed_control_plane.caller_deletion_tombstones WHERE tenant_id = '61000000-0000-4000-8000-000000000001'"

check_denied() {
  local label="$1"
  shift
  if PGPASSWORD=rt061-test psql -X -q -h 127.0.0.1 -U rt061_control_plane_login -d ${DB} -v ON_ERROR_STOP=1 "$@" >/dev/null 2>&1; then
    echo "RT-061 Control-plane smoke failed: application role unexpectedly allowed $label" >&2
    exit 1
  fi
}

check_denied "UPDATE" -c "UPDATE qembed_control_plane.caller_deletion_tombstones SET deleted_at = now()"
check_denied "DELETE" -c "DELETE FROM qembed_control_plane.caller_deletion_tombstones"
check_denied "TRUNCATE" -c "TRUNCATE qembed_control_plane.caller_deletion_tombstones"
check_denied "explicit sequence assignment" -c "INSERT INTO qembed_control_plane.caller_deletion_tombstones (sequence_id, tenant_id, caller_hash, key_version) VALUES (900, '61000000-0000-4000-8000-000000000001', decode(repeat('cd', 32), 'hex'), 'v1')"

count=$(PGPASSWORD=rt061-test psql -X -q -t -A -h 127.0.0.1 -U rt061_control_plane_login -d ${DB} -c "SELECT count(*) FROM qembed_control_plane.caller_deletion_tombstones")
[[ "$count" == "1" ]] || { echo "RT-061 Control-plane smoke failed: expected one immutable row, got $count" >&2; exit 1; }

echo "RT-061 Control-plane append-only schema smoke passed"
