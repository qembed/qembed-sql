\set A '''aaaaaaaa-0000-0000-0000-000000000001'''
SET client_min_messages=warning;
-- platform kill switch (superuser)
INSERT INTO kill_switches(id,scope_type,enabled,changed_by) VALUES ('f0000000-0000-0000-0000-000000000001','platform',false,'ops');
SET ROLE qembed_runtime;
SELECT set_config('app.tenant_id', :A, false) \gset
SELECT tt.chk('T-36 runtime reads platform ks', $q$SELECT count(*)=1 FROM kill_switches WHERE scope_type='platform'$q$);
SELECT tt.try('T-50 runtime INSERT platform ks','err',$q$INSERT INTO kill_switches(id,scope_type,enabled,changed_by) VALUES (gen_random_uuid(),'platform',true,'x')$q$);
SELECT tt.try('T-50 runtime UPDATE platform ks (0 rows)','ok',$q$UPDATE kill_switches SET enabled=true WHERE scope_type='platform'$q$);
SELECT tt.chk('T-50 platform ks unchanged', $q$SELECT enabled=false FROM kill_switches WHERE scope_type='platform'$q$);
SELECT tt.try('T-50 runtime DELETE platform ks','ok',$q$DELETE FROM kill_switches WHERE scope_type='platform'$q$);
SELECT tt.chk('T-50 platform ks still there', $q$SELECT count(*)=1 FROM kill_switches WHERE scope_type='platform'$q$);
-- definer functions callable by runtime
SELECT tt.chk('authenticate_principal', $q$SELECT count(*)=1 FROM authenticate_principal('\x01')$q$);
SELECT tt.try('resolve_object_tenant','ok',$q$SELECT resolve_object_tenant('0b000000-0000-0000-0000-000000000001')$q$);
SELECT tt.try('list_expired_invocation_leases','ok',$q$SELECT * FROM list_expired_invocation_leases(10)$q$);
SELECT tt.try('list_pending_reconciliations','ok',$q$SELECT * FROM list_pending_reconciliations(10)$q$);
SELECT tt.try('T-54 runtime cannot call retention_purge','err',$q$SELECT retention_purge('outbox_messages',now(),'x')$q$);
-- sweeper
SELECT tt.chk('sweeper is idempotent after RUST-041d expiry coverage', $q$SELECT sweep_expired_reservations(10)=0$q$);
SELECT tt.chk('T-40 sweeper idempotent', $q$SELECT sweep_expired_reservations(10)=0$q$);
SELECT tt.chk('usage_counters reserved released', $q$SELECT reserved_tokens=0 FROM usage_counters$q$);
SELECT tt.chk('R3-04 caller_usage_counters reserved released', $q$SELECT reserved_tokens=0 FROM caller_usage_counters$q$);
-- knowledge flow
SELECT tt.try('doc staged','ok',$q$INSERT INTO knowledge_documents(id,tenant_id,object_id,doc_key,title,status) VALUES ('d0c00000-0000-0000-0000-000000000001',current_setting('app.tenant_id')::uuid,'0b000000-0000-0000-0000-000000000001','faq','FAQ','staged')$q$);
SELECT tt.try('chunk staged','ok',$q$INSERT INTO knowledge_chunks(id,tenant_id,object_id,document_id,content,position) VALUES ('c4000000-0000-0000-0000-000000000001',current_setting('app.tenant_id')::uuid,'0b000000-0000-0000-0000-000000000001','d0c00000-0000-0000-0000-000000000001','hello',0)$q$);
SELECT tt.try('chunk invented interval denied','err',$q$INSERT INTO knowledge_chunks(id,tenant_id,object_id,document_id,content,position,valid_from_revision) VALUES (gen_random_uuid(),current_setting('app.tenant_id')::uuid,'0b000000-0000-0000-0000-000000000001','d0c00000-0000-0000-0000-000000000001','x',1,5)$q$);
SELECT tt.try('embedding dim ok','ok',$q$INSERT INTO knowledge_chunk_embeddings(tenant_id,object_id,chunk_id,model_id,embedding) VALUES (current_setting('app.tenant_id')::uuid,'0b000000-0000-0000-0000-000000000001','c4000000-0000-0000-0000-000000000001','m3','[1,2,3]')$q$);
SELECT tt.try('T-28 embedding dim mismatch','err',$q$UPDATE knowledge_chunk_embeddings SET embedding='[1,2]'$q$);
SELECT tt.try('revision commit rev1','ok',$q$
  UPDATE knowledge_revisions SET current_revision=1 WHERE object_id='0b000000-0000-0000-0000-000000000001';
  INSERT INTO knowledge_revision_log(tenant_id,object_id,revision) VALUES (current_setting('app.tenant_id')::uuid,'0b000000-0000-0000-0000-000000000001',1);
  UPDATE knowledge_documents SET status='live', valid_from_revision=1 WHERE id='d0c00000-0000-0000-0000-000000000001'$q$);
SELECT tt.chk('T-43 chunk interval synced', $q$SELECT valid_from_revision=1 AND valid_to_revision IS NULL FROM knowledge_chunks$q$);
SELECT tt.try('chunk interval direct UPDATE denied','err',$q$UPDATE knowledge_chunks SET valid_to_revision=9$q$);
SELECT tt.try('revision commit rev2 (replace doc)','ok',$q$
  UPDATE knowledge_revisions SET current_revision=2 WHERE object_id='0b000000-0000-0000-0000-000000000001';
  INSERT INTO knowledge_revision_log(tenant_id,object_id,revision) VALUES (current_setting('app.tenant_id')::uuid,'0b000000-0000-0000-0000-000000000001',2);
  UPDATE knowledge_documents SET status='retired', valid_to_revision=2 WHERE id='d0c00000-0000-0000-0000-000000000001';
  INSERT INTO knowledge_documents(id,tenant_id,object_id,doc_key,title,status,valid_from_revision) VALUES ('d0c00000-0000-0000-0000-000000000002',current_setting('app.tenant_id')::uuid,'0b000000-0000-0000-0000-000000000001','faq','FAQ2','live',2)$q$);
SELECT tt.try('KNOWN GAP (M2): runtime has no DELETE on knowledge_documents (GC)','err',$q$DELETE FROM knowledge_documents WHERE status='retired'$q$);
SELECT tt.try('R3-03 runtime cannot nullify terminal output directly','err',$q$UPDATE tool_executions SET output=NULL,output_expires_at=NULL WHERE id='ee000000-0000-0000-0000-000000000001'$q$);
RESET ROLE;
-- retention role
SET ROLE qembed_retention;
SELECT tt.try('T-61 retention events not allowed','err',$q$SELECT retention_purge('events',now(),'x')$q$);
SELECT tt.try('T-61 retention snapshots not allowed','err',$q$SELECT retention_purge('snapshots',now(),'x')$q$);
SELECT tt.try('retention interaction_messages','ok',$q$SELECT retention_purge('interaction_messages',now(),'ttl')$q$);
SELECT tt.try('R3-03 retention nullifies output of terminal tool_execution','ok',$q$SELECT retention_purge('tool_executions',now(),'ttl')$q$);
SELECT tt.try('retention memories','ok',$q$SELECT retention_purge('memories',now()+interval '1 year','ttl')$q$);
SELECT tt.try('retention direct DELETE denied','err',$q$DELETE FROM interaction_messages$q$);
RESET ROLE;
SELECT tt.chk('R3-03 output NULL, row still Succeeded', $q$SELECT output IS NULL AND status='Succeeded' FROM tool_executions WHERE id='ee000000-0000-0000-0000-000000000001'$q$);
-- dispatcher
SET ROLE qembed_dispatcher;
SELECT tt.chk('T-51 dispatcher reads delivery projection', $q$SELECT count(*)>=1 FROM outbox_messages$q$);
SELECT tt.try('T-51 dispatcher cannot read domain events','err',$q$SELECT count(*) FROM events$q$);
SELECT tt.try('T-51 dispatcher cannot read event identity','err',$q$SELECT event_id FROM outbox_messages LIMIT 1$q$);
SELECT tt.try('T-51 dispatcher callers denied','err',$q$SELECT * FROM callers$q$);
SELECT tt.try('T-51 dispatcher messages denied','err',$q$SELECT * FROM interaction_messages$q$);
SELECT tt.try('RUST-051a dispatcher claims delivery with fencing token','ok',$q$
  UPDATE outbox_messages
     SET lease_owner='sql-smoke-dispatcher',
         lease_expires_at=now()+interval '1 minute',
         claim_token=claim_token+1,
         attempts=attempts+1
   WHERE delivered_at IS NULL AND lease_owner IS NULL
     AND delivery_id=(SELECT delivery_id FROM outbox_messages
                       WHERE delivered_at IS NULL AND lease_owner IS NULL
                       ORDER BY created_at,delivery_id LIMIT 1)$q$);
SELECT tt.try('RUST-051a dispatcher acknowledges and releases lease','ok',$q$
  UPDATE outbox_messages
     SET delivered_at=now(), lease_owner=NULL, lease_expires_at=NULL
   WHERE delivered_at IS NULL AND lease_owner='sql-smoke-dispatcher'$q$);
SELECT tt.try('dispatcher INSERT outbox_messages denied','err',$q$INSERT INTO outbox_messages(delivery_id,tenant_id,event_id) VALUES (gen_random_uuid(),current_setting('app.tenant_id',true)::uuid,gen_random_uuid())$q$);
RESET ROLE;
-- retention may purge delivered rows, but must preserve pending deliveries
SET ROLE qembed_retention;
SELECT tt.try('AUDIT-005 retention purges delivered outbox rows','ok',$q$SELECT retention_purge('outbox_messages',now(),'ttl')$q$);
DO $receipt_history$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM outbox_publication_receipts
     WHERE tenant_id = current_setting('app.tenant_id')::uuid
  ) THEN
    RAISE EXCEPTION 'PubAck history was deleted with retained Outbox rows';
  END IF;
END
$receipt_history$;
RESET ROLE;
SELECT tt.chk('AUDIT-005 retention preserves pending outbox rows', $q$SELECT count(*)=1 AND bool_and(delivered_at IS NULL) FROM outbox_messages WHERE tenant_id=current_setting('app.tenant_id')::uuid$q$);
-- RLS audit & role attrs
SELECT tt.chk('T-54 role attrs', $q$SELECT count(*)=0 FROM pg_roles WHERE rolname LIKE 'qembed_%' AND rolname<>'qembed_migrator' AND (rolsuper OR rolbypassrls OR rolcanlogin)$q$);
SELECT tt.chk('T-57 definer fns have isolated owners, pinned search_path and no PUBLIC exec',
 $q$SELECT bool_and(
      NOT has_function_privilege('public',p.oid,'EXECUTE')
      AND prosecdef AND proconfig IS NOT NULL
      AND CASE WHEN proname='assign_event_stream_version'
          THEN pg_get_userbyid(proowner)='qembed_event_allocator'
               AND proconfig @> ARRAY['search_path=pg_catalog, public, pg_temp']
          ELSE pg_get_userbyid(proowner)='qembed_definer'
               AND proconfig @> ARRAY['search_path=pg_catalog, public, pg_temp']
      END)
    FROM pg_proc p
   WHERE pronamespace='public'::regnamespace AND prosecdef$q$);
