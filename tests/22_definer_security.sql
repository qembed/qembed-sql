-- AUDIT-010: SECURITY DEFINER ownership, search_path, grants and injection boundaries.
SET client_min_messages=warning;

-- QSA-002 adversarial fixtures. Created as the test owner before switching to runtime.
INSERT INTO embedding_models(id,provider,model_name,dimension,distance_metric)
VALUES ('qsa002-shadow-test','test','qsa002-shadow-test',3,'cosine')
ON CONFLICT (id) DO UPDATE SET dimension=3;
INSERT INTO objects(tenant_id,object_id,state)
VALUES ('aaaaaaaa-0000-0000-0000-000000000001','22000000-0000-0000-0000-000000000001','draft');
INSERT INTO object_versions(tenant_id,object_id,object_version_id,version_number,status)
VALUES ('aaaaaaaa-0000-0000-0000-000000000001','22000000-0000-0000-0000-000000000001','22000000-0000-0000-0000-000000000002',1,'draft');
INSERT INTO knowledge_documents(id,tenant_id,object_id,doc_key,title,status)
VALUES ('22000000-0000-0000-0000-000000000004','aaaaaaaa-0000-0000-0000-000000000001',
        '0b000000-0000-0000-0000-000000000001','qsa002-shadow','QSA-002 shadow fixture','staged');
INSERT INTO knowledge_chunks(id,tenant_id,object_id,document_id,content,position)
VALUES ('22000000-0000-0000-0000-000000000005','aaaaaaaa-0000-0000-0000-000000000001',
        '0b000000-0000-0000-0000-000000000001','22000000-0000-0000-0000-000000000004',
        'QSA-002 embedding dimension shadow fixture',1);

SELECT tt.chk('AUDIT-010 public schema is not writable by PUBLIC',
  $q$SELECT NOT has_schema_privilege('public','public','CREATE')$q$);
SELECT tt.chk('AUDIT-010 application roles cannot create in public',
  $q$SELECT bool_and(NOT has_schema_privilege(r,'public','CREATE'))
       FROM unnest(ARRAY['qembed_runtime','qembed_dispatcher','qembed_admin','qembed_retention','qembed_definer','qembed_event_allocator']) AS r$q$);

SET ROLE qembed_runtime;
SELECT set_config('app.tenant_id','aaaaaaaa-0000-0000-0000-000000000001',false);

-- QSA-002: temporary embedding_models must not override the trusted model dimension.
CREATE TEMP TABLE embedding_models(id text PRIMARY KEY, dimension integer);
INSERT INTO embedding_models VALUES ('qsa002-shadow-test',5);
SELECT tt.try('QSA-002 temporary model shadow cannot bypass embedding dimension guard','err',
  $q$INSERT INTO knowledge_chunk_embeddings(tenant_id,object_id,chunk_id,model_id,embedding)
     VALUES ('aaaaaaaa-0000-0000-0000-000000000001',
             '0b000000-0000-0000-0000-000000000001',
             '22000000-0000-0000-0000-000000000005',
             'qsa002-shadow-test','[1,2,3,4,5]'::vector)$q$);

-- QSA-002: temporary object_versions must not make a Draft version look Published.
UPDATE objects SET state='validating'
 WHERE tenant_id='aaaaaaaa-0000-0000-0000-000000000001'
   AND object_id='22000000-0000-0000-0000-000000000001';
CREATE TEMP TABLE object_versions(
  tenant_id uuid, object_id uuid, object_version_id uuid, status text
);
INSERT INTO object_versions VALUES
 ('aaaaaaaa-0000-0000-0000-000000000001',
  '22000000-0000-0000-0000-000000000001',
  '22000000-0000-0000-0000-000000000002','published');
SELECT tt.try('QSA-002 temporary version shadow cannot publish a Draft version','err',
  $q$UPDATE objects SET state='active', published_version_id='22000000-0000-0000-0000-000000000002'
     WHERE tenant_id='aaaaaaaa-0000-0000-0000-000000000001'
       AND object_id='22000000-0000-0000-0000-000000000001'$q$);

-- QSA-002: temporary event_stream_counters must not choose the assigned stream version.
CREATE TEMP TABLE event_stream_counters(
  tenant_id uuid NOT NULL, aggregate_type text NOT NULL, aggregate_id uuid NOT NULL,
  last_stream_version bigint NOT NULL,
  PRIMARY KEY(tenant_id,aggregate_type,aggregate_id)
);
INSERT INTO event_stream_counters VALUES
 ('aaaaaaaa-0000-0000-0000-000000000001','object',
  '22000000-0000-0000-0000-000000000001',4999);
GRANT ALL ON TABLE event_stream_counters TO qembed_event_allocator;
INSERT INTO events(tenant_id,event_id,aggregate_type,aggregate_id,event_type,payload)
VALUES ('aaaaaaaa-0000-0000-0000-000000000001','22000000-0000-0000-0000-000000000003',
        'object','22000000-0000-0000-0000-000000000001','qsa002.shadow.test','{}');
SELECT tt.chk('QSA-002 stream version came from trusted counter, not pg_temp',
  $q$SELECT e.stream_version=1
       AND (SELECT last_stream_version=4999 FROM pg_temp.event_stream_counters)
       FROM events e WHERE e.event_id='22000000-0000-0000-0000-000000000003'$q$);

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
SELECT tt.try('QSA-001 runtime cannot enumerate expired leases across tenants','err',
  $q$SELECT * FROM list_expired_invocation_leases(0)$q$);
SELECT tt.try('QSA-001 runtime cannot enumerate pending reconciliations across tenants','err',
  $q$SELECT * FROM list_pending_reconciliations(0)$q$);
SELECT tt.try('QSA-001 runtime cannot sweep cross-tenant reservations','err',
  $q$SELECT sweep_expired_reservations(0)$q$);
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
SET ROLE qembed_worker;
SELECT tt.chk('QSA-001 worker role is isolated and has only worker entry points',
  $q$SELECT NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls
       AND NOT pg_has_role('qembed_worker','qembed_definer','MEMBER')
       AND has_function_privilege('qembed_worker','public.list_expired_invocation_leases(integer)','EXECUTE')
       AND has_function_privilege('qembed_worker','public.list_pending_reconciliations(integer)','EXECUTE')
       AND has_function_privilege('qembed_worker','public.sweep_expired_reservations(integer)','EXECUTE')
       AND NOT has_function_privilege('qembed_worker','public.retention_purge(text,timestamptz,text)','EXECUTE')
       FROM pg_roles WHERE rolname='qembed_worker'$q$);
SELECT tt.chk('QSA-001 worker has no direct tenant data table access',
  $q$SELECT NOT has_table_privilege('qembed_worker','public.object_invocations','SELECT')
       AND NOT has_table_privilege('qembed_worker','public.tool_executions','SELECT')
       AND NOT has_table_privilege('qembed_worker','public.budget_reservations','SELECT')
       AND NOT has_table_privilege('qembed_worker','public.usage_counters','UPDATE')$q$);
SELECT tt.try('QSA-001 worker can call expired-lease discovery','ok',
  $q$SELECT count(*) FROM list_expired_invocation_leases(0)$q$);
SELECT tt.try('QSA-001 worker can call reconciliation discovery','ok',
  $q$SELECT count(*) FROM list_pending_reconciliations(0)$q$);
SELECT tt.try('QSA-001 worker can call reservation sweeper','ok',
  $q$SELECT sweep_expired_reservations(0)$q$);
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
SELECT tt.chk('AUDIT-010 allocator role is isolated and non-login',
  $q$SELECT NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls
       FROM pg_roles WHERE rolname='qembed_event_allocator'$q$);
SELECT tt.chk('AUDIT-010 no application role is a member of definer',
  $q$SELECT NOT pg_has_role('qembed_runtime','qembed_definer','MEMBER')
        AND NOT pg_has_role('qembed_dispatcher','qembed_definer','MEMBER')
        AND NOT pg_has_role('qembed_admin','qembed_definer','MEMBER')
        AND NOT pg_has_role('qembed_retention','qembed_definer','MEMBER')
        AND NOT pg_has_role('qembed_worker','qembed_definer','MEMBER')
        AND NOT pg_has_role('qembed_runtime','qembed_worker','MEMBER')$q$);

SELECT tt.chk('AUDIT-010 event stream allocator is an isolated definer trigger',
  $q$SELECT pg_get_userbyid(proowner)='qembed_event_allocator'
       AND prosecdef
       AND proconfig @> ARRAY['search_path=pg_catalog, public, pg_temp']
       AND NOT has_function_privilege('public',p.oid,'EXECUTE')
       FROM pg_proc p WHERE proname='assign_event_stream_version'
         AND pronamespace='public'::regnamespace$q$);
SELECT tt.chk('AUDIT-010 only isolated allocator can mutate stream counters',
  $q$SELECT has_table_privilege('qembed_event_allocator','public.event_stream_counters','UPDATE')
       AND NOT has_table_privilege('qembed_runtime','public.event_stream_counters','UPDATE')
       AND NOT has_table_privilege('qembed_dispatcher','public.event_stream_counters','UPDATE')
       AND NOT has_table_privilege('qembed_event_allocator','public.objects','SELECT')
       AND NOT has_table_privilege('qembed_event_allocator','public.events','INSERT')
       AND NOT pg_has_role('qembed_runtime','qembed_event_allocator','MEMBER')
       AND NOT pg_has_role('qembed_dispatcher','qembed_event_allocator','MEMBER')$q$);

SELECT tt.chk('QSA-002 every SECURITY DEFINER function pins pg_temp last',
  $q$SELECT count(*)=11 AND bool_and(
       proconfig @> ARRAY['search_path=pg_catalog, public, pg_temp'])
       FROM pg_proc p
       WHERE pronamespace='public'::regnamespace AND prosecdef$q$);
SELECT tt.chk('QSA-002 embedding and published-pointer trigger guards pin pg_temp last',
  $q$SELECT
       (SELECT proconfig @> ARRAY['search_path=pg_catalog, public, pg_temp']
          FROM pg_proc WHERE pronamespace='public'::regnamespace AND proname='check_embedding_dim')
       AND
       (SELECT proconfig @> ARRAY['search_path=pg_catalog, public, pg_temp']
          FROM pg_proc WHERE pronamespace='public'::regnamespace AND proname='object_published_pointer_guard')$q$);

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

SELECT tt.chk('QSA-001 runtime has only tenant-scoped operational definer entry points',
  $q$SELECT
       has_function_privilege('qembed_runtime','public.authenticate_principal(bytea)','EXECUTE')
       AND has_function_privilege('qembed_runtime','public.grant_caller_delegation(uuid)','EXECUTE')
       AND has_function_privilege('qembed_runtime','public.revoke_caller_delegation(uuid)','EXECUTE')
       AND has_function_privilege('qembed_runtime','public.resolve_delegated_caller(uuid)','EXECUTE')
       AND has_function_privilege('qembed_runtime','public.resolve_object_tenant(uuid)','EXECUTE')
       AND has_function_privilege('qembed_runtime','public.sweep_stale_invocation_deliveries(timestamp with time zone,integer)','EXECUTE')
       AND NOT has_function_privilege('qembed_runtime','public.list_expired_invocation_leases(integer)','EXECUTE')
       AND NOT has_function_privilege('qembed_runtime','public.list_pending_reconciliations(integer)','EXECUTE')
       AND NOT has_function_privilege('qembed_runtime','public.sweep_expired_reservations(integer)','EXECUTE')
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
