#!/usr/bin/env bash
# Qembed M0 v2.3.3 r3 — behavioural smoke suite. NOT a replacement for T-01..T-64 CI.
# Usage: SCHEMA=../qembed_m0_v2_3_3_clean_schema.sql DB=qembed_smoke ./run_smoke.sh
# Needs a PostgreSQL superuser connection (PGHOST/PGUSER/...), pgvector >= 0.8.0 and a role
# 'qembed_migrator' (SUPERUSER here, only for the smoke run). Drops and recreates $DB.
set -u
cd "$(dirname "$0")"
SCHEMA=${SCHEMA:-../qembed_m0_v2_3_3_clean_schema.sql}
DB=${DB:-qembed_smoke}
P="psql -X -q -v ON_ERROR_STOP=1 -d $DB"
psql -X -q -d postgres -c "DROP DATABASE IF EXISTS $DB" -c "CREATE DATABASE $DB" || exit 2
$P -f "$SCHEMA" || { echo "SCHEMA APPLY FAILED"; exit 2; }
psql -X -q -d $DB -c "DO \$\$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='rt_login') THEN CREATE ROLE rt_login LOGIN PASSWORD 'x' IN ROLE qembed_runtime; END IF; END \$\$" >/dev/null
for f in 00_harness.sql 01_fixtures.sql 05_rust_physical_contract.sql 06_owner_authentication.sql 07_principal_caller_delegation.sql 10_objects_rls.sql 15_snapshots.sql 16_events_outbox.sql 17_tenant_rls.sql 18_object_lifecycle.sql 19_composite_tenant_fks.sql 20_invocations_memory_tools.sql 21_invocation_lifecycle.sql 30_roles_knowledge_retention.sql 22_definer_security.sql 40_unknown_admin_hnsw.sql; do
  psql -X -q -t -A -d $DB -f "$f" >/dev/null 2>/tmp/smoke_err.$$ || { echo "ERROR in $f"; cat /tmp/smoke_err.$$; }
done
# real login: runtime must not be able to SET ROLE qembed_definer
if PGPASSWORD=x psql -X -q -h 127.0.0.1 -U rt_login -d $DB -c "SET ROLE qembed_definer" 2>/dev/null; then
  psql -X -q -d $DB -c "INSERT INTO tt.res VALUES ('T-54 runtime real login cannot SET ROLE definer','err','ok',false,'')"
else
  psql -X -q -d $DB -c "INSERT INTO tt.res VALUES ('T-54 runtime real login cannot SET ROLE definer','err','err',true,'')"
fi
psql -X -t -A -d $DB -c "SELECT 'FAIL | '||label||' | expected '||expect||' got '||got||' | '||detail FROM tt.res WHERE NOT ok"
psql -X -t -A -d $DB -c "SELECT 'TOTAL '||count(*)||'  PASSED '||count(*) FILTER (WHERE ok)||'  FAILED '||count(*) FILTER (WHERE NOT ok) FROM tt.res"
