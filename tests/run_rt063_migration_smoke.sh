#!/usr/bin/env bash
# Upgrade the canonical schema with durable invocation Knowledge pins and safe GC.
set -euo pipefail
cd "$(dirname "$0")"

DB=${DB:-qembed_rt063_migration}
psql -X -q -d postgres -c "DROP DATABASE IF EXISTS ${DB}" -c "CREATE DATABASE ${DB}"
P="psql -X -q -v ON_ERROR_STOP=1 -d ${DB}"

base_schema_commit=573a54a56797e713131e74c4830b3bcb6181abaf
git fetch --quiet --depth 1 origin "$base_schema_commit"
schema_path="${TMPDIR:-/tmp}/qembed_pre_rt063_schema.sql"
git show "$base_schema_commit:qembed_m0_v2_3_3_clean_schema.sql" > "$schema_path"

$P -f "$schema_path"
$P -f qembed_context_verify_transaction_setup.sql
$P -f qsa003_signed_context_seed.sql
$P -f ../migrations/rt050_signed_context_rls.sql
$P -f ../migrations/rt063_knowledge_revision_pinning_gc.sql

check() {
  local label="$1"
  local sql="$2"
  local result
  result="$($P -Atc "$sql")"
  if [[ "$result" != "t" ]]; then
    echo "RT-063 migration smoke failed: $label (got: $result)" >&2
    exit 1
  fi
}

check "revision pin table has forced RLS and signed tenant policy" \
  "SELECT c.relrowsecurity AND c.relforcerowsecurity AND EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid=c.oid AND p.polname='tenant_isolation' AND pg_get_expr(p.polqual,p.polrelid) LIKE '%current_tenant_id%') FROM pg_class c WHERE c.oid='public.knowledge_revision_pins'::regclass"
check "pin table has invocation and revision-log foreign keys" \
  "SELECT count(*)=2 FROM pg_constraint WHERE conrelid='public.knowledge_revision_pins'::regclass AND contype='f'"
check "runtime pin privileges are read/insert only" \
  "SELECT has_table_privilege('qembed_runtime','public.knowledge_revision_pins','SELECT') AND has_table_privilege('qembed_runtime','public.knowledge_revision_pins','INSERT') AND NOT has_table_privilege('qembed_runtime','public.knowledge_revision_pins','UPDATE') AND NOT has_table_privilege('qembed_runtime','public.knowledge_revision_pins','DELETE')"
check "terminal release trigger exists" \
  "SELECT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid='public.object_invocations'::regclass AND tgname='trg_release_terminal_invocation_knowledge_pin' AND NOT tgisinternal)"
check "tenant-scoped GC function is runtime callable and definer owned" \
  "SELECT has_function_privilege('qembed_runtime','public.collect_retired_knowledge_documents(uuid,uuid,integer)','EXECUTE') AND pg_get_userbyid((SELECT proowner FROM pg_proc WHERE oid='public.collect_retired_knowledge_documents(uuid,uuid,integer)'::regprocedure))='qembed_definer'"

$P -c "SELECT public.assert_tenant_rls_classification()" >/dev/null
echo "RT-063 Knowledge revision pinning and GC migration smoke passed"
