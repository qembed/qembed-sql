\set A '''aaaaaaaa-0000-0000-0000-000000000001'''
SET client_min_messages=warning;
SET ROLE qembed_runtime;
SELECT set_config('app.tenant_id', :A, false) \gset
SELECT tt.try('decision2 Allow','ok',$q$INSERT INTO policy_decisions(id,tenant_id,object_id,invocation_id,caller_id,snapshot_id,tool_id,tool_version_id,binding_version,operation,arguments_hash,action_hash,risk_level,decision,policy_version,command_id,issued_at,expires_at)
 VALUES ('d2000000-0000-0000-0000-000000000001',current_setting('app.tenant_id')::uuid,'0b000000-0000-0000-0000-000000000001','1a000000-0000-0000-0000-000000000001','ca000000-0000-0000-0000-000000000001','5a000000-0000-0000-0000-000000000001','11111111-0000-0000-0000-000000000001','11111111-0000-0000-0000-0000000000a2',2,'op2',digest('a2','sha256'),digest('b2','sha256'),'R2','Allow','p1','c0000000-0000-0000-0000-000000000002',now(),now()+interval '5 min')$q$);
SELECT tt.try('exec2 Authorized','ok',$q$INSERT INTO tool_executions(id,tenant_id,object_id,invocation_id,caller_id,decision_id,command_id,tool_id,tool_version_id,snapshot_id,binding_version,operation,arguments_hash,status)
 VALUES ('ee000000-0000-0000-0000-000000000002',current_setting('app.tenant_id')::uuid,'0b000000-0000-0000-0000-000000000001','1a000000-0000-0000-0000-000000000001','ca000000-0000-0000-0000-000000000001','d2000000-0000-0000-0000-000000000001','c0000000-0000-0000-0000-000000000002','11111111-0000-0000-0000-000000000001','11111111-0000-0000-0000-0000000000a2','5a000000-0000-0000-0000-000000000001',2,'op2',digest('a2','sha256'),'Authorized')$q$);
SELECT tt.try('exec2 ->Executing, lease already expired','ok',$q$UPDATE tool_executions SET status='Executing',lease_owner='w1',lease_until=now()-interval '1 min',fencing_token=1 WHERE id='ee000000-0000-0000-0000-000000000002'$q$);
SELECT tt.try('T-59 expired Executing ->Succeeded denied','err',$q$UPDATE tool_executions SET status='Succeeded',finished_at=now(),lease_owner=NULL,lease_until=NULL WHERE id='ee000000-0000-0000-0000-000000000002'$q$);
SELECT tt.try('T-59 expired Executing ->Unknown','ok',$q$UPDATE tool_executions SET status='Unknown',reconciliation_state='pending',lease_owner=NULL,lease_until=NULL WHERE id='ee000000-0000-0000-0000-000000000002'$q$);
SELECT tt.try('T-59 Unknown ->Succeeded w/ state pending denied','err',$q$UPDATE tool_executions SET status='Succeeded',finished_at=now() WHERE id='ee000000-0000-0000-0000-000000000002'$q$);
SELECT tt.try('R3-05 Unknown ->Succeeded with reconciliation_state NULL denied','err',$q$UPDATE tool_executions SET status='Succeeded',reconciliation_state=NULL,finished_at=now() WHERE id='ee000000-0000-0000-0000-000000000002'$q$);
SELECT tt.try('R3-05 Unknown ->Succeeded with confirmed_failed denied','err',$q$UPDATE tool_executions SET status='Succeeded',reconciliation_state='confirmed_failed',finished_at=now() WHERE id='ee000000-0000-0000-0000-000000000002'$q$);
SELECT tt.chk('exec2 still Unknown', $q$SELECT status='Unknown' FROM tool_executions WHERE id='ee000000-0000-0000-0000-000000000002'$q$);
SELECT tt.try('T-59 Unknown ->Succeeded via proper reconciliation','ok',$q$UPDATE tool_executions SET status='Succeeded',reconciliation_state='confirmed_succeeded',finished_at=now() WHERE id='ee000000-0000-0000-0000-000000000002'$q$);
RESET ROLE;
-- admin creating an object (provisioning)
SET ROLE qembed_admin;
SELECT tt.try('R3-06 admin provisions object','ok',$q$INSERT INTO objects(object_id,tenant_id,state) VALUES (gen_random_uuid(),'bbbbbbbb-0000-0000-0000-000000000002','Draft')$q$);
RESET ROLE;
-- HNSW creation as migrator (concurrently, outside txn)
CREATE INDEX CONCURRENTLY hnsw_m3 ON knowledge_chunk_embeddings USING hnsw ((embedding::vector(3)) vector_cosine_ops) WHERE model_id='m3';
SELECT tt.chk('HNSW partial index built', $q$SELECT count(*)=1 FROM pg_indexes WHERE indexname='hnsw_m3'$q$);
