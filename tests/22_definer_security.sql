-- AUDIT-010: SECURITY DEFINER ownership, search_path, grants and injection boundaries.
SET client_min_messages=warning;

SELECT tt.chk('AUDIT-010 public schema is not writable by PUBLIC',
  $q$SELECT NOT has_schema_privilege('public','public','CREATE')$q$);
SELECT tt.chk('AUDIT-010 application roles cannot create in public',
  $q$SELECT bool_and(NOT has_schema_privilege(r,'public','CREATE'))
       FROM unnest(ARRAY['qembed_runtime','qembed_dispatcher','qembed_admin','qembed_retention','qembed_definer']) AS r$q$);

SET ROLE qembed_runtime;
-- A caller may create temporary objects, but they must not shadow relations used
-- by SECURITY DEFINER functions: pg_temp is explicitly last in their search_path.
CREATE TEMP TABLE principals (
  id uuid, tenant_id uuid, kind text, key_hash bytea, revoked_at timestamptz
);
INSERT INTO principals VALUES
  ('99999999-0000-0000-0000-000000000099',
   'bbbbbbbb-0000-0000-0000-000000000002','TenantOwner','\x01',NULL);
CREATE TEMP TABLE objects (object_id uuid, tenant_id uuid);
SELECT tt.chk('AUDIT-010 authenticate_principal ignores temporary shadow table',
  $q$SELECT EXISTS (SELECT 1 FROM authenticate_principal('\x01')
       WHERE principal_id='22222222-0000-0000-0000-00000000000a')$q$);
SELECT tt.chk('AUDIT-010 resolve_object_tenant ignores temporary shadow table',
  $q$SELECT resolve_object_tenant('0b000000-0000-0000-0000-000000000001')
       = 'aaaaaaaa-0000-0000-0000-000000000001'::uuid$q$);
SELECT tt.try('AUDIT-010 runtime cannot create objects in SECURITY DEFINER search_path', 'err',
  $q$CREATE FUNCTION public.audit010_shadow() RETURNS integer LANGUAGE sql AS 'SELECT 1'$q$);
SELECT tt.try('AUDIT-010 runtime cannot execute retention_purge', 'err',
  $q$SELECT retention_purge('interaction_messages',now(),'runtime')$q$);
RESET ROLE;

SET ROLE qembed_admin;
SELECT tt.try('AUDIT-010 admin cannot execute sweeper', 'err',
  $q$SELECT sweep_expired_reservations(1)$q$);
SELECT tt.try('AUDIT-010 admin cannot execute retention', 'err',
  $q$SELECT retention_purge('interaction_messages',now(),'admin')$q$);
RESET ROLE;

SET ROLE qembed_dispatcher;
SELECT tt.try('AUDIT-010 dispatcher cannot execute cross-tenant discovery', 'err',
  $q$SELECT * FROM list_expired_invocation_leases(1)$q$);
RESET ROLE;

SET ROLE qembed_retention;
SELECT tt.try('AUDIT-010 retention role can execute allowlisted purge', 'ok',
  $q$SELECT retention_purge('interaction_messages',now(),'AUDIT-010 allowlisted action')$q$);
SELECT tt.try('AUDIT-010 arbitrary SQL in table argument is rejected', 'err',
  $q$SELECT retention_purge('interaction_messages''; DROP TABLE objects;--',now(),'injection')$q$);
SELECT tt.try('AUDIT-010 reason is persisted as literal data', 'ok',
  $q$SELECT retention_purge('interaction_messages',now(),'AUDIT-010 literal ''; DROP TABLE objects; --')$q$);
RESET ROLE;

SELECT tt.chk('AUDIT-010 rejected table argument did not execute injected SQL',
  $q$SELECT to_regclass('public.objects') IS NOT NULL$q$);
SELECT tt.chk('AUDIT-010 reason payload was stored literally',
  $q$SELECT EXISTS (SELECT 1 FROM retention_log
       WHERE reason = 'AUDIT-010 literal ''; DROP TABLE objects; --')$q$);

SELECT tt.chk('AUDIT-010 definer role is isolated and non-login',
  $q$SELECT NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls
       FROM pg_roles WHERE rolname='qembed_definer'$q$);
SELECT tt.chk('AUDIT-010 no application role is a member of definer',
  $q$SELECT NOT pg_has_role('qembed_runtime','qembed_definer','MEMBER')
        AND NOT pg_has_role('qembed_dispatcher','qembed_definer','MEMBER')
        AND NOT pg_has_role('qembed_admin','qembed_definer','MEMBER')
        AND NOT pg_has_role('qembed_retention','qembed_definer','MEMBER')$q$);

SELECT tt.chk('AUDIT-010 SECURITY DEFINER functions are owned, pinned and not PUBLIC-executable',
  $q$SELECT count(*)=9 AND bool_and(
       pg_get_userbyid(proowner)='qembed_definer'
       AND prosecdef
       AND proconfig @> ARRAY['search_path=pg_catalog, public, pg_temp']
       AND NOT has_function_privilege('public',p.oid,'EXECUTE'))
       FROM pg_proc p
       WHERE pronamespace='public'::regnamespace
         AND proname IN ('authenticate_principal','grant_caller_delegation','revoke_caller_delegation','resolve_delegated_caller','resolve_object_tenant',
                         'list_expired_invocation_leases','list_pending_reconciliations',
                         'sweep_expired_reservations','retention_purge')$q$);

SELECT tt.chk('AUDIT-010 runtime has only its eight operational definer entry points',
  $q$SELECT
       has_function_privilege('qembed_runtime','public.authenticate_principal(bytea)','EXECUTE')
       AND has_function_privilege('qembed_runtime','public.grant_caller_delegation(uuid)','EXECUTE')
       AND has_function_privilege('qembed_runtime','public.revoke_caller_delegation(uuid)','EXECUTE')
       AND has_function_privilege('qembed_runtime','public.resolve_delegated_caller(uuid)','EXECUTE')
       AND has_function_privilege('qembed_runtime','public.resolve_object_tenant(uuid)','EXECUTE')
       AND has_function_privilege('qembed_runtime','public.list_expired_invocation_leases(integer)','EXECUTE')
       AND has_function_privilege('qembed_runtime','public.list_pending_reconciliations(integer)','EXECUTE')
       AND has_function_privilege('qembed_runtime','public.sweep_expired_reservations(integer)','EXECUTE')
       AND NOT has_function_privilege('qembed_runtime','public.retention_purge(text,timestamptz,text)','EXECUTE')$q$);
SELECT tt.chk('AUDIT-010 retention has only the purge entry point',
  $q$SELECT has_function_privilege('qembed_retention','public.retention_purge(text,timestamptz,text)','EXECUTE')
        AND NOT has_function_privilege('qembed_retention','public.sweep_expired_reservations(integer)','EXECUTE')
        AND NOT has_function_privilege('qembed_retention','public.list_expired_invocation_leases(integer)','EXECUTE')$q$);
SELECT tt.chk('AUDIT-010 admin and dispatcher have no SECURITY DEFINER entry points',
  $q$SELECT NOT has_function_privilege('qembed_admin','public.authenticate_principal(bytea)','EXECUTE')
        AND NOT has_function_privilege('qembed_admin','public.grant_caller_delegation(uuid)','EXECUTE')
        AND NOT has_function_privilege('qembed_admin','public.revoke_caller_delegation(uuid)','EXECUTE')
        AND NOT has_function_privilege('qembed_dispatcher','public.grant_caller_delegation(uuid)','EXECUTE')
        AND NOT has_function_privilege('qembed_dispatcher','public.revoke_caller_delegation(uuid)','EXECUTE')
        AND NOT has_function_privilege('qembed_admin','public.resolve_delegated_caller(uuid)','EXECUTE')
        AND NOT has_function_privilege('qembed_dispatcher','public.resolve_delegated_caller(uuid)','EXECUTE')
        AND NOT has_function_privilege('qembed_admin','public.retention_purge(text,timestamptz,text)','EXECUTE')
        AND NOT has_function_privilege('qembed_dispatcher','public.list_pending_reconciliations(integer)','EXECUTE')
        AND NOT has_function_privilege('qembed_dispatcher','public.sweep_expired_reservations(integer)','EXECUTE')$q$);

SELECT tt.chk('AUDIT-010 definer table grants remain least-privilege',
  $q$SELECT
       has_table_privilege('qembed_definer','public.objects','SELECT')
       AND NOT has_table_privilege('qembed_definer','public.objects','UPDATE')
       AND has_table_privilege('qembed_definer','public.tool_executions','SELECT')
       AND has_table_privilege('qembed_definer','public.tool_executions','UPDATE')
       AND NOT has_table_privilege('qembed_definer','public.tool_executions','DELETE')
       AND has_table_privilege('qembed_definer','public.retention_log','INSERT')
       AND NOT has_table_privilege('qembed_definer','public.retention_log','SELECT')
       AND has_column_privilege('qembed_definer','public.owner_principals','disabled_at','UPDATE')
       AND has_column_privilege('qembed_definer','public.callers','revoked_at','UPDATE')
       AND has_table_privilege('qembed_definer','public.principal_caller_delegations','SELECT')
       AND has_table_privilege('qembed_definer','public.principal_caller_delegations','INSERT')
       AND has_table_privilege('qembed_definer','public.principal_caller_delegations','UPDATE')
       AND NOT has_table_privilege('qembed_definer','public.principal_caller_delegations','DELETE')
       AND NOT has_table_privilege('qembed_definer','public.snapshots','SELECT')$q$);
