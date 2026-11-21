\set A '''aaaaaaaa-0000-0000-0000-000000000001'''
SET client_min_messages=warning;
SET ROLE qembed_runtime;
SELECT set_config('app.tenant_id', :A, false) \gset
-- callers
SELECT tt.try('callers','ok',$q$INSERT INTO callers(id,tenant_id,token_hash,caller_kind) VALUES
 ('ca000000-0000-0000-0000-000000000001',current_setting('app.tenant_id')::uuid,'\x11','Authenticated'),
 ('ca000000-0000-0000-0000-000000000002',current_setting('app.tenant_id')::uuid,'\x12','Anonymous')$q$);
-- Snapshot persistence follows the Rust physical contract: exact canonical bytes,
-- their fixed-width digest, and a derived JSONB query projection. The database
-- checks projection consistency; cryptographic hash verification belongs to Rust.
CREATE TEMP TABLE sj AS SELECT convert_to('{"k":2}','UTF8') AS b;
SELECT tt.try('snapshot insert ok','ok',$q$INSERT INTO snapshots(tenant_id,snapshot_id,object_id,object_version_id,schema_version,canonical_json,content_hash,json_projection)
 SELECT current_setting('app.tenant_id')::uuid,'5a000000-0000-0000-0000-000000000001','0b000000-0000-0000-0000-000000000001','0c000000-0000-0000-0000-000000000002',1,b,digest(b,'sha256'),convert_from(b,'UTF8')::jsonb FROM sj$q$);
SELECT tt.try('snapshot hash verification remains at Rust read boundary','ok',$q$INSERT INTO snapshots(tenant_id,snapshot_id,object_id,object_version_id,schema_version,canonical_json,content_hash,json_projection)
 SELECT current_setting('app.tenant_id')::uuid,gen_random_uuid(),'0b000000-0000-0000-0000-000000000001','0c000000-0000-0000-0000-000000000002',1,b,decode(repeat('01',32),'hex'),convert_from(b,'UTF8')::jsonb FROM sj$q$);
SELECT tt.try('snapshot projection mismatch rejected','err',$q$INSERT INTO snapshots(tenant_id,snapshot_id,object_id,object_version_id,schema_version,canonical_json,content_hash,json_projection)
 SELECT current_setting('app.tenant_id')::uuid,gen_random_uuid(),'0b000000-0000-0000-0000-000000000001','0c000000-0000-0000-0000-000000000002',1,b,digest(b,'sha256'),'{"k":3}'::jsonb FROM sj$q$);
SELECT tt.try('snapshot UPDATE denied','err',$q$UPDATE snapshots SET json_projection='{"tampered":true}'::jsonb$q$);
SELECT tt.try('snapshot DELETE denied','err',$q$DELETE FROM snapshots$q$);
-- budgets
SELECT tt.try('budget row','ok',$q$INSERT INTO object_budgets VALUES (current_setting('app.tenant_id')::uuid,'0b000000-0000-0000-0000-000000000001',1000000,1000000,50,100000,5,5,5,10000,60000)$q$);
SELECT tt.try('usage counter rows','ok',$q$INSERT INTO usage_counters(tenant_id,object_id,usage_date,pool,reserved_tokens,reserved_cost_micros) VALUES (current_setting('app.tenant_id')::uuid,'0b000000-0000-0000-0000-000000000001',current_date,'authenticated',500,500)$q$);
SELECT tt.try('caller usage counter','ok',$q$INSERT INTO caller_usage_counters(tenant_id,object_id,caller_id,usage_date,reserved_tokens) VALUES (current_setting('app.tenant_id')::uuid,'0b000000-0000-0000-0000-000000000001','ca000000-0000-0000-0000-000000000001',current_date,500)$q$);
-- begin invocation (idempotency first, deferred FK) T-06/T-29
SELECT tt.try('BEGIN invocation txn','ok',$q$
 INSERT INTO invocation_idempotency(tenant_id,object_id,caller_id,idempotency_key,payload_hash,invocation_id,expires_at)
   VALUES (current_setting('app.tenant_id')::uuid,'0b000000-0000-0000-0000-000000000001','ca000000-0000-0000-0000-000000000001','k1','\x00','1a000000-0000-0000-0000-000000000001',now()+interval '1 day');
 INSERT INTO object_invocations(id,tenant_id,object_id,caller_id,snapshot_id,knowledge_revision,pool,status,trace_id)
   VALUES ('1a000000-0000-0000-0000-000000000001',current_setting('app.tenant_id')::uuid,'0b000000-0000-0000-0000-000000000001','ca000000-0000-0000-0000-000000000001','5a000000-0000-0000-0000-000000000001',0,'authenticated','Received',gen_random_uuid());
 INSERT INTO budget_reservations(id,tenant_id,object_id,invocation_id,pool,usage_date,reserved_tokens,reserved_cost_micros,status,expires_at)
   VALUES ('b1000000-0000-0000-0000-000000000001',current_setting('app.tenant_id')::uuid,'0b000000-0000-0000-0000-000000000001','1a000000-0000-0000-0000-000000000001','authenticated',current_date,500,500,'Reserved',now()-interval '1 minute');
 INSERT INTO events(event_id,tenant_id,aggregate_type,aggregate_id,event_type,payload)
   VALUES ('e1000000-0000-0000-0000-000000000001',current_setting('app.tenant_id')::uuid,'invocation','1a000000-0000-0000-0000-000000000001','InvocationReceived','{}');
 INSERT INTO outbox_messages(delivery_id,tenant_id,event_id,topic,payload)
   VALUES (gen_random_uuid(),current_setting('app.tenant_id')::uuid,'e1000000-0000-0000-0000-000000000001','invocation.events','{}')$q$);
SELECT tt.try('T-06 dup idempotency key','err',$q$INSERT INTO invocation_idempotency(tenant_id,object_id,caller_id,idempotency_key,payload_hash,invocation_id,expires_at) VALUES (current_setting('app.tenant_id')::uuid,'0b000000-0000-0000-0000-000000000001','ca000000-0000-0000-0000-000000000001','k1','\x00','1a000000-0000-0000-0000-000000000001',now()+interval '1 day')$q$);
SELECT tt.try('T-29 duplicate event_id rejected','err',$q$INSERT INTO events(event_id,tenant_id,aggregate_type,aggregate_id,event_type,payload) VALUES ('e1000000-0000-0000-0000-000000000001',current_setting('app.tenant_id')::uuid,'invocation','1a000000-0000-0000-0000-000000000001','duplicate','{}')$q$);
SELECT tt.try('T-42 message caller mismatch','err',$q$INSERT INTO interaction_messages(id,tenant_id,object_id,caller_id,invocation_id,role,content,expires_at) VALUES (gen_random_uuid(),current_setting('app.tenant_id')::uuid,'0b000000-0000-0000-0000-000000000001','ca000000-0000-0000-0000-000000000002','1a000000-0000-0000-0000-000000000001','user','hi',now()+interval '1 day')$q$);
SELECT tt.try('message ok (expired for purge)','ok',$q$INSERT INTO interaction_messages(id,tenant_id,object_id,caller_id,invocation_id,role,content,expires_at) VALUES (gen_random_uuid(),current_setting('app.tenant_id')::uuid,'0b000000-0000-0000-0000-000000000001','ca000000-0000-0000-0000-000000000001','1a000000-0000-0000-0000-000000000001','user','hi',now()-interval '1 day')$q$);
SELECT tt.try('T-09 events UPDATE denied','err',$q$UPDATE events SET event_type='y'$q$);
-- memory
SELECT tt.try('candidate semantic User/Unverified','ok',$q$INSERT INTO memories(id,tenant_id,object_id,memory_kind,claim,source_kind,verification,confidence) VALUES ('de000000-0000-0000-0000-000000000001',current_setting('app.tenant_id')::uuid,'0b000000-0000-0000-0000-000000000001','semantic','c','User','Unverified',0.5)$q$);
SELECT tt.try('T-60 UPDATE candidate->Verified denied','err',$q$UPDATE memories SET verification='Verified',source_kind='Owner',verified_by='22222222-0000-0000-0000-00000000000a',verified_at=now() WHERE id='de000000-0000-0000-0000-000000000001'$q$);
SELECT tt.try('T-60 TenantAdmin Verified denied','err',$q$INSERT INTO memories(id,tenant_id,object_id,memory_kind,claim,source_kind,verification,confidence,supersedes_id,verified_by,verified_at) VALUES (gen_random_uuid(),current_setting('app.tenant_id')::uuid,'0b000000-0000-0000-0000-000000000001','semantic','c','Owner','Verified',1,'de000000-0000-0000-0000-000000000001','22222222-0000-0000-0000-00000000000b',now())$q$);
SELECT tt.try('T-60 Owner Verified row accepted','ok',$q$INSERT INTO memories(id,tenant_id,object_id,memory_kind,claim,source_kind,verification,confidence,supersedes_id,verified_by,verified_at) VALUES ('de000000-0000-0000-0000-000000000002',current_setting('app.tenant_id')::uuid,'0b000000-0000-0000-0000-000000000001','semantic','c','Owner','Verified',1,'de000000-0000-0000-0000-000000000001','22222222-0000-0000-0000-00000000000a',now())$q$);
SELECT tt.try('R3-02 direct UPDATE of Verified row (supersedes_id=NULL) denied','err',$q$UPDATE memories SET supersedes_id=NULL WHERE id='de000000-0000-0000-0000-000000000002'$q$);
SELECT tt.try('R3-02 delete superseded candidate (FK SET NULL on Verified row)','ok',$q$DELETE FROM memories WHERE id='de000000-0000-0000-0000-000000000001'$q$);
SELECT tt.chk('R3-02 Verified row kept, supersedes_id NULL', $q$SELECT verification='Verified' AND supersedes_id IS NULL FROM memories WHERE id='de000000-0000-0000-0000-000000000002'$q$);
-- tool binding
SELECT tt.try('bind tool v1','ok',$q$INSERT INTO object_tools(tenant_id,object_id,tool_id,tool_version_id,permissions) VALUES (current_setting('app.tenant_id')::uuid,'0b000000-0000-0000-0000-000000000001','11111111-0000-0000-0000-000000000001','11111111-0000-0000-0000-0000000000a1','{}')$q$);
SELECT tt.chk('binding_version=1', $q$SELECT binding_version=1 FROM object_tools$q$);
SELECT tt.try('rebind v2','ok',$q$UPDATE object_tools SET tool_version_id='11111111-0000-0000-0000-0000000000a2'$q$);
SELECT tt.chk('binding_version=2 monotonic', $q$SELECT binding_version=2 FROM object_tools$q$);
SELECT tt.try('T-47 DELETE binding denied','err',$q$DELETE FROM object_tools$q$);
-- policy decision + execution
SELECT tt.try('decision Allow','ok',$q$INSERT INTO policy_decisions(id,tenant_id,object_id,invocation_id,caller_id,snapshot_id,tool_id,tool_version_id,binding_version,operation,arguments_hash,action_hash,risk_level,decision,policy_version,command_id,issued_at,expires_at)
 VALUES ('d1000000-0000-0000-0000-000000000001',current_setting('app.tenant_id')::uuid,'0b000000-0000-0000-0000-000000000001','1a000000-0000-0000-0000-000000000001','ca000000-0000-0000-0000-000000000001','5a000000-0000-0000-0000-000000000001','11111111-0000-0000-0000-000000000001','11111111-0000-0000-0000-0000000000a2',2,'op',digest('a','sha256'),digest('b','sha256'),'R2','Allow','p1','c0000000-0000-0000-0000-000000000001',now(),now()+interval '5 min')$q$);
SELECT tt.try('decision claim mismatch caller','err',$q$INSERT INTO policy_decisions(id,tenant_id,object_id,invocation_id,caller_id,snapshot_id,tool_id,tool_version_id,binding_version,operation,arguments_hash,action_hash,risk_level,decision,policy_version,command_id,issued_at,expires_at)
 VALUES (gen_random_uuid(),current_setting('app.tenant_id')::uuid,'0b000000-0000-0000-0000-000000000001','1a000000-0000-0000-0000-000000000001','ca000000-0000-0000-0000-000000000002','5a000000-0000-0000-0000-000000000001','11111111-0000-0000-0000-000000000001','11111111-0000-0000-0000-0000000000a2',2,'op',digest('a','sha256'),digest('b','sha256'),'R2','Allow','p1',gen_random_uuid(),now(),now()+interval '5 min')$q$);
SELECT tt.try('payload ok','ok',$q$INSERT INTO tool_command_payloads(tenant_id,command_id,payload_ciphertext,key_id,arguments_hash,expires_at) VALUES (current_setting('app.tenant_id')::uuid,'c0000000-0000-0000-0000-000000000001','\xdead','k1',digest('a','sha256'),now()+interval '1 hour')$q$);
SELECT tt.try('payload hash mismatch','err',$q$UPDATE tool_command_payloads SET arguments_hash=digest('zz','sha256')$q$);
SELECT tt.try('exec Authorized','ok',$q$INSERT INTO tool_executions(id,tenant_id,object_id,invocation_id,caller_id,decision_id,command_id,tool_id,tool_version_id,snapshot_id,binding_version,operation,arguments_hash,status)
 VALUES ('ee000000-0000-0000-0000-000000000001',current_setting('app.tenant_id')::uuid,'0b000000-0000-0000-0000-000000000001','1a000000-0000-0000-0000-000000000001','ca000000-0000-0000-0000-000000000001','d1000000-0000-0000-0000-000000000001','c0000000-0000-0000-0000-000000000001','11111111-0000-0000-0000-000000000001','11111111-0000-0000-0000-0000000000a2','5a000000-0000-0000-0000-000000000001',2,'op',digest('a','sha256'),'Authorized')$q$);
SELECT tt.chk('ToolExecution starts with its own version/token zero',
 $q$SELECT version=0 AND fencing_token=0 AND lease_owner IS NULL AND heartbeat_at IS NULL
      FROM tool_executions WHERE id='ee000000-0000-0000-0000-000000000001'$q$);
SELECT tt.try('exec ->Executing acquires independent lease','ok',$q$UPDATE tool_executions
 SET status='Executing',lease_owner='tool-worker-a',lease_until=now()+interval '1 min',
     heartbeat_at=now(),fencing_token=1,version=1
 WHERE id='ee000000-0000-0000-0000-000000000001'$q$);
SELECT tt.chk('ToolExecution claim advances only its own version/token',
 $q$SELECT version=1 AND fencing_token=1 AND lease_owner='tool-worker-a'
      AND heartbeat_at IS NOT NULL FROM tool_executions
      WHERE id='ee000000-0000-0000-0000-000000000001'$q$);
SELECT tt.try('ToolExecution heartbeat retains version and fence','ok',$q$UPDATE tool_executions
 SET lease_until=now()+interval '2 min',heartbeat_at=now()
 WHERE id='ee000000-0000-0000-0000-000000000001'$q$);
SELECT tt.chk('heartbeat does not advance version or fencing token',
 $q$SELECT version=1 AND fencing_token=1 FROM tool_executions
      WHERE id='ee000000-0000-0000-0000-000000000001'$q$);
SELECT tt.try('heartbeat can refresh without shortening a longer lease','ok',$q$UPDATE tool_executions
 SET lease_until=lease_until,heartbeat_at=clock_timestamp()
 WHERE id='ee000000-0000-0000-0000-000000000001'$q$);
SELECT tt.try('heartbeat cannot shorten an existing lease','err',$q$UPDATE tool_executions
 SET lease_until=now()+interval '1 second',heartbeat_at=clock_timestamp()
 WHERE id='ee000000-0000-0000-0000-000000000001'$q$);

SELECT tt.try('stale ToolExecution fence cannot commit','err',$q$UPDATE tool_executions
 SET status='Succeeded',lease_owner=NULL,lease_until=NULL,heartbeat_at=NULL,
     finished_at=now(),version=2,fencing_token=0
 WHERE id='ee000000-0000-0000-0000-000000000001'$q$);
SELECT tt.try('exec ->Succeeded w/ output','ok',$q$UPDATE tool_executions
 SET status='Succeeded',lease_owner=NULL,lease_until=NULL,heartbeat_at=NULL,
     finished_at=now(),version=2,output='{"r":1}',output_expires_at=now()-interval '1 hour'
 WHERE id='ee000000-0000-0000-0000-000000000001'$q$);
SELECT tt.chk('ToolExecution completion increments own version only',
 $q$SELECT version=2 AND fencing_token=1 AND lease_owner IS NULL
      FROM tool_executions WHERE id='ee000000-0000-0000-0000-000000000001'$q$);
SELECT tt.try('exec terminal immutable','err',$q$UPDATE tool_executions SET operation='z' WHERE id='ee000000-0000-0000-0000-000000000001'$q$);

RESET ROLE;

-- RUST-046 / T-04 + T-21: provenance claims must be rejected by PostgreSQL,
-- not merely by the application path. These are deliberately direct INSERTs.
SELECT tt.try('T-04 User cannot claim Verified','err',$q$INSERT INTO memories(id,tenant_id,object_id,memory_kind,claim,source_kind,verification,confidence,verified_by,verified_at)
 VALUES (gen_random_uuid(),current_setting('app.tenant_id')::uuid,'0b000000-0000-0000-0000-000000000001','semantic','user verified','User','Verified',1,'22222222-0000-0000-0000-00000000000a',now())$q$);
SELECT tt.try('T-04 ThirdParty cannot claim Observed','err',$q$INSERT INTO memories(id,tenant_id,object_id,memory_kind,claim,source_kind,verification,confidence)
 VALUES (gen_random_uuid(),current_setting('app.tenant_id')::uuid,'0b000000-0000-0000-0000-000000000001','semantic','third-party observed','ThirdParty','Observed',0.8)$q$);
SELECT tt.try('T-04 RuntimeInference cannot claim Verified','err',$q$INSERT INTO memories(id,tenant_id,object_id,memory_kind,claim,source_kind,verification,confidence,verified_by,verified_at)
 VALUES (gen_random_uuid(),current_setting('app.tenant_id')::uuid,'0b000000-0000-0000-0000-000000000001','semantic','inferred verified','RuntimeInference','Verified',1,'22222222-0000-0000-0000-00000000000a',now())$q$);
SELECT tt.try('T-21 TrustedDocument cannot create Verified without Owner promotion row','err',$q$INSERT INTO memories(id,tenant_id,object_id,memory_kind,claim,source_kind,verification,confidence,supersedes_id,verified_by,verified_at)
 VALUES (gen_random_uuid(),current_setting('app.tenant_id')::uuid,'0b000000-0000-0000-0000-000000000001','semantic','trusted document verified','TrustedDocument','Verified',1,'de000000-0000-0000-0000-000000000002','22222222-0000-0000-0000-00000000000a',now())$q$);
SELECT tt.try('T-21 User Observed is invalid','err',$q$INSERT INTO memories(id,tenant_id,object_id,memory_kind,claim,source_kind,verification,confidence)
 VALUES (gen_random_uuid(),current_setting('app.tenant_id')::uuid,'0b000000-0000-0000-0000-000000000001','semantic','user observed','User','Observed',0.5)$q$);
SELECT tt.try('T-21 Tool Observed is valid','ok',$q$INSERT INTO memories(id,tenant_id,object_id,memory_kind,claim,source_kind,verification,confidence)
 VALUES ('de000000-0000-0000-0000-000000000003',current_setting('app.tenant_id')::uuid,'0b000000-0000-0000-0000-000000000001','semantic','tool observed','Tool','Observed',0.9)$q$);

-- T-27 caller isolation has dedicated DB/RLS coverage in 24_caller_memory_rls.sql.
