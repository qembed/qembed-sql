-- QSA-003: executable evidence of the legacy session-GUC trust boundary.
-- These assertions intentionally demonstrate the current weakness; they do not
-- claim that legacy GUC identity is secure. The signed-context migration must
-- invert these outcomes before QSA-003 can be VERIFIED.
\set ON_ERROR_STOP on
SET client_min_messages=warning;

-- tests/17_tenant_rls.sql has seeded both tenant rows.
SET ROLE qembed_runtime;
SELECT set_config('app.tenant_id','aaaaaaaa-0000-0000-0000-000000000001',false);
SELECT tt.chk('QSA-003 baseline tenant A cannot see tenant B object',
  $q$SELECT count(*)=0 FROM objects
      WHERE tenant_id='bbbbbbbb-0000-0000-0000-000000000002'
        AND object_id='bb000000-0000-0000-0000-000000000001'$q$);

-- The same runtime session chooses B's identity GUC and now reads B's row.
-- This is the reported bypass, recorded as an expected current-risk assertion.
SELECT set_config('app.tenant_id','bbbbbbbb-0000-0000-0000-000000000002',false);
SELECT tt.chk('QSA-003 runtime can forge tenant GUC and read tenant B object',
  $q$SELECT count(*)=1 FROM objects
      WHERE tenant_id='bbbbbbbb-0000-0000-0000-000000000002'
        AND object_id='bb000000-0000-0000-0000-000000000001'$q$);

-- tests/07_principal_caller_delegation.sql created a TenantAdmin Principal B.
-- Even if the legacy GUC is forged, the new delegation function independently
-- enforces TenantOwner authority and rejects Principal B.
SELECT set_config('app.tenant_id','d1100000-0000-0000-0000-000000000001',false);
SELECT set_config('app.principal_id','d1110000-0000-0000-0000-000000000002',false);
SELECT tt.try('QSA-003 forged TenantAdmin GUC cannot grant Caller delegation','err',
  $q$SELECT grant_caller_delegation('d1120000-0000-0000-0000-000000000001')$q$);

-- tests/24_caller_memory_rls.sql created two delegated Callers and episodic rows.
-- Directly setting app.caller_id bypasses resolve_delegated_caller's lock/check
-- path and switches the visible episodic-memory identity.
SELECT set_config('app.tenant_id','c2700000-0000-0000-0000-000000000001',false);
SELECT set_config('app.caller_id','c2720000-0000-0000-0000-000000000001',false);
SELECT tt.chk('QSA-003 Caller A GUC hides Caller B episodic memory',
  $q$SELECT count(*)=0 FROM memories
      WHERE id='c2740000-0000-0000-0000-000000000003'$q$);
SELECT set_config('app.caller_id','c2720000-0000-0000-0000-000000000002',false);
SELECT tt.chk('QSA-003 runtime can forge Caller B GUC and read Caller B episodic memory',
  $q$SELECT count(*)=1 FROM memories
      WHERE id='c2740000-0000-0000-0000-000000000003'$q$);

RESET ROLE;
