-- M1a acceptance gap regressions: T-20, T-29, T-53 and T-55.
\set ON_ERROR_STOP on
SET client_min_messages=warning;

-- T-20: a published snapshot pins the exact ToolVersion even after the live
-- Object binding is changed. ToolVersion rows are immutable/global; bindings
-- are mutable, snapshots are not.
SET ROLE qembed_runtime;
SELECT set_config('app.tenant_id', 'aaaaaaaa-0000-0000-0000-000000000001', false);
UPDATE object_tools
   SET tool_version_id='11111111-0000-0000-0000-0000000000a1'
 WHERE tenant_id='aaaaaaaa-0000-0000-0000-000000000001'
   AND object_id='0b000000-0000-0000-0000-000000000001'
   AND tool_id='11111111-0000-0000-0000-000000000001';
INSERT INTO snapshots(tenant_id,snapshot_id,object_id,object_version_id,schema_version,
                      canonical_json,content_hash,json_projection)
VALUES ('aaaaaaaa-0000-0000-0000-000000000001',
        '25000000-0000-0000-0000-000000000001',
        '0b000000-0000-0000-0000-000000000001',
        '0c000000-0000-0000-0000-000000000002',1,
        convert_to('{"tool_bindings":[{"tool_id":"11111111-0000-0000-0000-000000000001","tool_version_id":"11111111-0000-0000-0000-0000000000a1"}]}','UTF8'),
        digest(convert_to('{"tool_bindings":[{"tool_id":"11111111-0000-0000-0000-000000000001","tool_version_id":"11111111-0000-0000-0000-0000000000a1"}]}','UTF8'),'sha256'),
        '{"tool_bindings":[{"tool_id":"11111111-0000-0000-0000-000000000001","tool_version_id":"11111111-0000-0000-0000-0000000000a1"}]}'::jsonb);
UPDATE object_tools
   SET tool_version_id='11111111-0000-0000-0000-0000000000a2'
 WHERE tenant_id='aaaaaaaa-0000-0000-0000-000000000001'
   AND object_id='0b000000-0000-0000-0000-000000000001'
   AND tool_id='11111111-0000-0000-0000-000000000001';
SELECT tt.chk('T-20 snapshot keeps ToolVersion v1 after live binding moves to v2',
 $q$SELECT s.json_projection #>> '{tool_bindings,0,tool_version_id}'='11111111-0000-0000-0000-0000000000a1'
       AND b.tool_version_id='11111111-0000-0000-0000-0000000000a2'
    FROM snapshots s JOIN object_tools b USING (tenant_id,object_id)
   WHERE s.snapshot_id='25000000-0000-0000-0000-000000000001'
     AND b.tool_id='11111111-0000-0000-0000-000000000001'$q$);

-- T-29: trigger-assigned stream versions are monotonic per aggregate and
-- independent aggregates each start at one. No client-supplied version can win.
INSERT INTO events(tenant_id,event_id,aggregate_type,aggregate_id,event_type,payload)
VALUES ('aaaaaaaa-0000-0000-0000-000000000001','29000000-0000-0000-0000-000000000001',
        'invocation','29000000-0000-0000-0000-000000000010','created','{}'),
       ('aaaaaaaa-0000-0000-0000-000000000001','29000000-0000-0000-0000-000000000002',
        'invocation','29000000-0000-0000-0000-000000000010','started','{}'),
       ('aaaaaaaa-0000-0000-0000-000000000001','29000000-0000-0000-0000-000000000003',
        'invocation','29000000-0000-0000-0000-000000000011','created','{}');
SELECT tt.chk('T-29 stream versions increment independently per aggregate',
 $q$SELECT (SELECT array_agg(stream_version ORDER BY stream_version)=ARRAY[1,2]::bigint[]
              FROM events WHERE aggregate_id='29000000-0000-0000-0000-000000000010')
       AND (SELECT min(stream_version)=1 AND max(stream_version)=1
              FROM events WHERE aggregate_id='29000000-0000-0000-0000-000000000011')$q$);
SELECT tt.try('T-29 caller cannot choose stream_version','err',
 $q$INSERT INTO events(tenant_id,event_id,aggregate_type,aggregate_id,stream_version,event_type,payload)
    VALUES ('aaaaaaaa-0000-0000-0000-000000000001',gen_random_uuid(),'invocation',
            '29000000-0000-0000-0000-000000000010',999,'forged','{}')$q$);
RESET ROLE;

-- T-53: migration guard must abort when a tenant-owned table is omitted from
-- RLS classification, not merely report it after the migration has completed.
CREATE TABLE public.tt_unclassified_tenant_probe(tenant_id uuid NOT NULL);
SELECT tt.try('T-53 RLS migration guard rejects unclassified tenant table','err',
 $q$SELECT assert_tenant_rls_classification()$q$);
DROP TABLE public.tt_unclassified_tenant_probe;

-- T-55: cross-claim integrity. Build a second Object/snapshot under the same
-- tenant, then ensure decision/execution rows cannot mix its claims.
INSERT INTO objects(tenant_id,object_id,state)
VALUES ('aaaaaaaa-0000-0000-0000-000000000001',
        '55000000-0000-0000-0000-000000000001','draft');
INSERT INTO object_versions(tenant_id,object_id,object_version_id,version_number,status)
VALUES ('aaaaaaaa-0000-0000-0000-000000000001',
        '55000000-0000-0000-0000-000000000001',
        '55000000-0000-0000-0000-000000000002',1,'draft');
INSERT INTO snapshots(tenant_id,snapshot_id,object_id,object_version_id,schema_version,
                      canonical_json,content_hash,json_projection)
VALUES ('aaaaaaaa-0000-0000-0000-000000000001',
        '55000000-0000-0000-0000-000000000003',
        '55000000-0000-0000-0000-000000000001',
        '55000000-0000-0000-0000-000000000002',1,
        convert_to('{}','UTF8'),digest(convert_to('{}','UTF8'),'sha256'),'{}'::jsonb);

SET ROLE qembed_runtime;
SELECT set_config('app.tenant_id', 'aaaaaaaa-0000-0000-0000-000000000001', false);
SELECT tt.try('T-55 decision cannot claim another same-tenant Object snapshot','err',
 $q$INSERT INTO policy_decisions(id,tenant_id,object_id,invocation_id,caller_id,snapshot_id,tool_id,tool_version_id,binding_version,operation,arguments_hash,action_hash,risk_level,decision,policy_version,command_id,issued_at,expires_at)
    VALUES (gen_random_uuid(),'aaaaaaaa-0000-0000-0000-000000000001','0b000000-0000-0000-0000-000000000001',
    '1a000000-0000-0000-0000-000000000001','ca000000-0000-0000-0000-000000000001',
    '55000000-0000-0000-0000-000000000003','11111111-0000-0000-0000-000000000001',
    '11111111-0000-0000-0000-0000000000a1',1,'op',digest('a','sha256'),digest('b','sha256'),
    'R2','Allow','p1',gen_random_uuid(),now(),now()+interval '5 min')$q$);
SELECT tt.try('T-55 decision cannot pair Tool ID with another ToolVersion','err',
 $q$INSERT INTO policy_decisions(id,tenant_id,object_id,invocation_id,caller_id,snapshot_id,tool_id,tool_version_id,binding_version,operation,arguments_hash,action_hash,risk_level,decision,policy_version,command_id,issued_at,expires_at)
    VALUES (gen_random_uuid(),'aaaaaaaa-0000-0000-0000-000000000001','0b000000-0000-0000-0000-000000000001',
    '1a000000-0000-0000-0000-000000000001','ca000000-0000-0000-0000-000000000001',
    '5a000000-0000-0000-0000-000000000001','11111111-0000-0000-0000-000000000001',
    '55000000-0000-0000-0000-000000000099',1,'op',digest('a','sha256'),digest('b','sha256'),
    'R2','Allow','p1',gen_random_uuid(),now(),now()+interval '5 min')$q$);

-- A valid decision and a second valid decision provide two existing command IDs.
INSERT INTO policy_decisions(id,tenant_id,object_id,invocation_id,caller_id,snapshot_id,tool_id,tool_version_id,binding_version,operation,arguments_hash,action_hash,risk_level,decision,policy_version,command_id,issued_at,expires_at)
VALUES
 ('55000000-0000-0000-0000-000000000010','aaaaaaaa-0000-0000-0000-000000000001','0b000000-0000-0000-0000-000000000001','1a000000-0000-0000-0000-000000000001','ca000000-0000-0000-0000-000000000001','5a000000-0000-0000-0000-000000000001','11111111-0000-0000-0000-000000000001','11111111-0000-0000-0000-0000000000a1',1,'op-a',digest('a','sha256'),digest('aa','sha256'),'R2','Allow','p1','55000000-0000-0000-0000-000000000020',now(),now()+interval '5 min'),
 ('55000000-0000-0000-0000-000000000011','aaaaaaaa-0000-0000-0000-000000000001','0b000000-0000-0000-0000-000000000001','1a000000-0000-0000-0000-000000000001','ca000000-0000-0000-0000-000000000001','5a000000-0000-0000-0000-000000000001','11111111-0000-0000-0000-000000000001','11111111-0000-0000-0000-0000000000a2',2,'op-b',digest('b','sha256'),digest('bb','sha256'),'R2','Allow','p1','55000000-0000-0000-0000-000000000021',now(),now()+interval '5 min');
SELECT tt.try('T-55 execution cannot combine decision A with command B','err',
 $q$INSERT INTO tool_executions(id,tenant_id,object_id,invocation_id,caller_id,decision_id,command_id,tool_id,tool_version_id,snapshot_id,binding_version,operation,arguments_hash,status)
    VALUES (gen_random_uuid(),'aaaaaaaa-0000-0000-0000-000000000001','0b000000-0000-0000-0000-000000000001','1a000000-0000-0000-0000-000000000001','ca000000-0000-0000-0000-000000000001','55000000-0000-0000-0000-000000000010','55000000-0000-0000-0000-000000000021','11111111-0000-0000-0000-000000000001','11111111-0000-0000-0000-0000000000a1','5a000000-0000-0000-0000-000000000001',1,'op-a',digest('a','sha256'),'Authorized')$q$);
SELECT tt.try('T-55 execution cannot change the decision ToolVersion','err',
 $q$INSERT INTO tool_executions(id,tenant_id,object_id,invocation_id,caller_id,decision_id,command_id,tool_id,tool_version_id,snapshot_id,binding_version,operation,arguments_hash,status)
    VALUES (gen_random_uuid(),'aaaaaaaa-0000-0000-0000-000000000001','0b000000-0000-0000-0000-000000000001','1a000000-0000-0000-0000-000000000001','ca000000-0000-0000-0000-000000000001','55000000-0000-0000-0000-000000000010','55000000-0000-0000-0000-000000000020','11111111-0000-0000-0000-000000000001','11111111-0000-0000-0000-0000000000a2','5a000000-0000-0000-0000-000000000001',1,'op-a',digest('a','sha256'),'Authorized')$q$);
SELECT tt.try('T-55 execution cannot change snapshot claim','err',
 $q$INSERT INTO tool_executions(id,tenant_id,object_id,invocation_id,caller_id,decision_id,command_id,tool_id,tool_version_id,snapshot_id,binding_version,operation,arguments_hash,status)
    VALUES (gen_random_uuid(),'aaaaaaaa-0000-0000-0000-000000000001','0b000000-0000-0000-0000-000000000001','1a000000-0000-0000-0000-000000000001','ca000000-0000-0000-0000-000000000001','55000000-0000-0000-0000-000000000010','55000000-0000-0000-0000-000000000020','11111111-0000-0000-0000-000000000001','11111111-0000-0000-0000-0000000000a1','55000000-0000-0000-0000-000000000003',1,'op-a',digest('a','sha256'),'Authorized')$q$);
SELECT tt.try('T-55 execution cannot change the Invocation Caller claim','err',
 $q$INSERT INTO tool_executions(id,tenant_id,object_id,invocation_id,caller_id,decision_id,command_id,tool_id,tool_version_id,snapshot_id,binding_version,operation,arguments_hash,status)
    VALUES (gen_random_uuid(),'aaaaaaaa-0000-0000-0000-000000000001','0b000000-0000-0000-0000-000000000001','1a000000-0000-0000-0000-000000000001','ca000000-0000-0000-0000-000000000002','55000000-0000-0000-0000-000000000010','55000000-0000-0000-0000-000000000020','11111111-0000-0000-0000-000000000001','11111111-0000-0000-0000-0000000000a1','5a000000-0000-0000-0000-000000000001',1,'op-a',digest('a','sha256'),'Authorized')$q$);
SELECT tt.try('T-55 execution cannot change the Object claim within a tenant','err',
 $q$INSERT INTO tool_executions(id,tenant_id,object_id,invocation_id,caller_id,decision_id,command_id,tool_id,tool_version_id,snapshot_id,binding_version,operation,arguments_hash,status)
    VALUES (gen_random_uuid(),'aaaaaaaa-0000-0000-0000-000000000001','55000000-0000-0000-0000-000000000001','1a000000-0000-0000-0000-000000000001','ca000000-0000-0000-0000-000000000001','55000000-0000-0000-0000-000000000010','55000000-0000-0000-0000-000000000020','11111111-0000-0000-0000-000000000001','11111111-0000-0000-0000-0000000000a1','5a000000-0000-0000-0000-000000000001',1,'op-a',digest('a','sha256'),'Authorized')$q$);
RESET ROLE;
