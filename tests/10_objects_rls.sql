\set A '''aaaaaaaa-0000-0000-0000-000000000001'''
\set B '''bbbbbbbb-0000-0000-0000-000000000002'''
SET client_min_messages=warning;
SET ROLE qembed_runtime;
SELECT set_config('app.tenant_id', :A, false);
-- objects & versions
SELECT tt.try('rt create object O1 (Draft)','ok',$q$INSERT INTO objects(object_id,tenant_id,state) VALUES ('0b000000-0000-0000-0000-000000000001',current_setting('app.tenant_id')::uuid,'draft')$q$);
SELECT tt.chk('knowledge_revisions auto-init', $q$SELECT count(*)=1 FROM knowledge_revisions$q$);
SELECT tt.try('rt create v1 draft','ok',$q$INSERT INTO object_versions(object_version_id,tenant_id,object_id,version_number,config,chat_model_ref,embedding_model_id) VALUES ('0c000000-0000-0000-0000-000000000001',current_setting('app.tenant_id')::uuid,'0b000000-0000-0000-0000-000000000001',1,'{}','x:y','m3')$q$);
SELECT tt.try('publish v1 (txn: version->published, pointer, Active)','ok',$q$
  UPDATE object_versions SET status='published', published_at=now() WHERE object_version_id='0c000000-0000-0000-0000-000000000001';
  UPDATE objects SET published_version_id='0c000000-0000-0000-0000-000000000001', state='active' WHERE object_id='0b000000-0000-0000-0000-000000000001'$q$);
SELECT tt.chk('object Active w/ v1', $q$SELECT state='active' AND published_version_id='0c000000-0000-0000-0000-000000000001' FROM objects$q$);
SELECT tt.try('rt create v2 draft','ok',$q$INSERT INTO object_versions(object_version_id,tenant_id,object_id,version_number,config,chat_model_ref,embedding_model_id) VALUES ('0c000000-0000-0000-0000-000000000002',current_setting('app.tenant_id')::uuid,'0b000000-0000-0000-0000-000000000001',2,'{"k":2}','x:y','m3')$q$);
SELECT tt.try('R3-01 republish v2 (supersede v1, publish v2, move pointer) in one txn','ok',$q$
  UPDATE object_versions SET status='superseded' WHERE object_version_id='0c000000-0000-0000-0000-000000000001';
  UPDATE object_versions SET status='published', published_at=now() WHERE object_version_id='0c000000-0000-0000-0000-000000000002';
  UPDATE objects SET published_version_id='0c000000-0000-0000-0000-000000000002' WHERE object_id='0b000000-0000-0000-0000-000000000001';
  SET CONSTRAINTS ALL IMMEDIATE$q$);
SELECT tt.chk('R3-01 object points to v2, v1 superseded', $q$SELECT published_version_id='0c000000-0000-0000-0000-000000000002' AND (SELECT status FROM object_versions WHERE object_version_id='0c000000-0000-0000-0000-000000000001')='superseded' FROM objects$q$);
SELECT tt.try('R3-01 negative: supersede current version without moving pointer must fail at COMMIT','err',$q$
  UPDATE object_versions SET status='superseded' WHERE object_version_id='0c000000-0000-0000-0000-000000000002';
  SET CONSTRAINTS ALL IMMEDIATE$q$);
SELECT tt.try('R3-01 negative: pointer to a superseded version denied','err',$q$UPDATE objects SET published_version_id='0c000000-0000-0000-0000-000000000001' WHERE object_id='0b000000-0000-0000-0000-000000000001'$q$);
-- cross-tenant
SELECT tt.chk('T-01 A cannot see B (none yet) / rls on', $q$SELECT count(*) = 1 FROM objects$q$);
SELECT tt.try('T-01 write into tenant B denied','err',$q$INSERT INTO objects(object_id,tenant_id,state) VALUES (gen_random_uuid(),'bbbbbbbb-0000-0000-0000-000000000002','draft')$q$);
SELECT set_config('app.tenant_id','',false);
SELECT tt.chk('T-49 no scope => 0 rows', $q$SELECT count(*)=0 FROM objects$q$);
SELECT tt.try('T-49 no scope write denied','err',$q$INSERT INTO objects(object_id,tenant_id,state) VALUES (gen_random_uuid(),'aaaaaaaa-0000-0000-0000-000000000001','draft')$q$);
SELECT set_config('app.tenant_id', :A, false);
RESET ROLE;
