-- T-27: Caller-level isolation for episodic memory and dependent tables.
-- resolve_delegated_caller establishes app.caller_id in the same transaction.
\set ON_ERROR_STOP on
SET client_min_messages=warning;

INSERT INTO tenants(id) VALUES ('c2700000-0000-0000-0000-000000000001');
INSERT INTO owner_principals(tenant_id,caller_id,principal_kind) VALUES
 ('c2700000-0000-0000-0000-000000000001','c2710000-0000-0000-0000-000000000001','tenant_owner');
INSERT INTO callers(id,tenant_id,token_hash,caller_kind) VALUES
 ('c2720000-0000-0000-0000-000000000001','c2700000-0000-0000-0000-000000000001',digest('t27-caller-a','sha256'),'Authenticated'),
 ('c2720000-0000-0000-0000-000000000002','c2700000-0000-0000-0000-000000000001',digest('t27-caller-b','sha256'),'Authenticated');
INSERT INTO objects(tenant_id,object_id,state) VALUES
 ('c2700000-0000-0000-0000-000000000001','c2730000-0000-0000-0000-000000000001','draft');
INSERT INTO embedding_models(id,provider,model_name,dimension,distance_metric)
VALUES ('m3_t27','test','t27',3,'cosine');

INSERT INTO memories(id,tenant_id,object_id,caller_id,memory_kind,claim,source_kind,verification,confidence,expires_at) VALUES
 ('c2740000-0000-0000-0000-000000000001','c2700000-0000-0000-0000-000000000001','c2730000-0000-0000-0000-000000000001','c2720000-0000-0000-0000-000000000001','episodic','caller A memory 1','User','Unverified',0.5,now()+interval '1 day'),
 ('c2740000-0000-0000-0000-000000000002','c2700000-0000-0000-0000-000000000001','c2730000-0000-0000-0000-000000000001','c2720000-0000-0000-0000-000000000001','episodic','caller A memory 2','User','Unverified',0.5,now()+interval '1 day'),
 ('c2740000-0000-0000-0000-000000000003','c2700000-0000-0000-0000-000000000001','c2730000-0000-0000-0000-000000000001','c2720000-0000-0000-0000-000000000002','episodic','caller B secret','User','Unverified',0.5,now()+interval '1 day');
INSERT INTO memories(id,tenant_id,object_id,memory_kind,claim,source_kind,verification,confidence)
VALUES ('c2740000-0000-0000-0000-000000000004','c2700000-0000-0000-0000-000000000001','c2730000-0000-0000-0000-000000000001','semantic','tenant semantic memory','User','Unverified',0.5);

INSERT INTO memory_embeddings(tenant_id,object_id,memory_id,model_id,embedding) VALUES
 ('c2700000-0000-0000-0000-000000000001','c2730000-0000-0000-0000-000000000001','c2740000-0000-0000-0000-000000000001','m3','[1,0,0]'),
 ('c2700000-0000-0000-0000-000000000001','c2730000-0000-0000-0000-000000000001','c2740000-0000-0000-0000-000000000003','m3','[0,1,0]');
INSERT INTO memory_conflicts(id,tenant_id,object_id,memory_id,conflicting_memory_id,status) VALUES
 ('c2750000-0000-0000-0000-000000000001','c2700000-0000-0000-0000-000000000001','c2730000-0000-0000-0000-000000000001','c2740000-0000-0000-0000-000000000001','c2740000-0000-0000-0000-000000000002','open'),
 ('c2750000-0000-0000-0000-000000000002','c2700000-0000-0000-0000-000000000001','c2730000-0000-0000-0000-000000000001','c2740000-0000-0000-0000-000000000001','c2740000-0000-0000-0000-000000000003','open');

SET ROLE qembed_runtime;
BEGIN;
SELECT set_config('app.tenant_id','c2700000-0000-0000-0000-000000000001',true);
SELECT set_config('app.principal_id','c2710000-0000-0000-0000-000000000001',true);
SELECT grant_caller_delegation('c2720000-0000-0000-0000-000000000001');
SELECT grant_caller_delegation('c2720000-0000-0000-0000-000000000002');

-- No Caller context: semantic rows remain tenant-scoped; episodic rows fail closed.
SELECT set_config('app.caller_id','',true);
SELECT tt.chk('T-27 missing Caller context hides episodic memory',
 $q$SELECT count(*)=0 FROM memories WHERE memory_kind='episodic'$q$);
SELECT tt.chk('T-27 semantic memory remains tenant-scoped',
 $q$SELECT count(*)=1 FROM memories WHERE memory_kind='semantic' AND id='c2740000-0000-0000-0000-000000000004'$q$);

-- Resolving Caller A sets transaction-local app.caller_id from the validated delegation.
SELECT * FROM resolve_delegated_caller('c2720000-0000-0000-0000-000000000001');
SELECT tt.chk('T-27 resolver installs Caller A transaction context',
 $q$SELECT current_setting('app.caller_id',true)='c2720000-0000-0000-0000-000000000001'$q$);
SELECT tt.chk('T-27 Caller A sees own episodic memories',
 $q$SELECT count(*)=2 FROM memories WHERE memory_kind='episodic'$q$);
SELECT tt.chk('T-27 Caller A cannot see Caller B episodic memory',
 $q$SELECT count(*)=0 FROM memories WHERE id='c2740000-0000-0000-0000-000000000003'$q$);
SELECT tt.chk('T-27 Caller A sees own embedding only',
 $q$SELECT count(*)=1 FROM memory_embeddings$q$);
SELECT tt.chk('T-27 Caller A cannot see Caller B embedding',
 $q$SELECT count(*)=0 FROM memory_embeddings WHERE memory_id='c2740000-0000-0000-0000-000000000003'$q$);
SELECT tt.chk('T-27 Caller A sees conflict between own memories',
 $q$SELECT count(*)=1 FROM memory_conflicts WHERE id='c2750000-0000-0000-0000-000000000001'$q$);
SELECT tt.chk('T-27 Caller A cannot see conflict edge to Caller B',
 $q$SELECT count(*)=0 FROM memory_conflicts WHERE id='c2750000-0000-0000-0000-000000000002'$q$);
SELECT tt.try('T-27 Caller A cannot insert Caller B episodic memory','err',
 $q$INSERT INTO memories(id,tenant_id,object_id,caller_id,memory_kind,claim,source_kind,verification,confidence,expires_at)
 VALUES ('c2740000-0000-0000-0000-000000000005','c2700000-0000-0000-0000-000000000001','c2730000-0000-0000-0000-000000000001','c2720000-0000-0000-0000-000000000002','episodic','forged caller B','User','Unverified',0.5,now()+interval '1 day')$q$);
SELECT tt.try('T-27 Caller A cannot create embedding for Caller B memory','err',
 $q$INSERT INTO memory_embeddings(tenant_id,object_id,memory_id,model_id,embedding)
 VALUES ('c2700000-0000-0000-0000-000000000001','c2730000-0000-0000-0000-000000000001','c2740000-0000-0000-0000-000000000003','m3_t27','[0,0,1]')$q$);
SELECT tt.try('T-27 Caller A cannot create conflict edge to Caller B','err',
 $q$INSERT INTO memory_conflicts(id,tenant_id,object_id,memory_id,conflicting_memory_id,status)
 VALUES ('c2750000-0000-0000-0000-000000000003','c2700000-0000-0000-0000-000000000001','c2730000-0000-0000-0000-000000000001','c2740000-0000-0000-0000-000000000001','c2740000-0000-0000-0000-000000000003','open')$q$);
SELECT tt.try('T-27 Caller A update of Caller B memory affects no row','ok',
 $q$UPDATE memories SET claim='tampered' WHERE id='c2740000-0000-0000-0000-000000000003'$q$);
SELECT tt.try('T-27 Caller A delete of Caller B memory affects no row','ok',
 $q$DELETE FROM memories WHERE id='c2740000-0000-0000-0000-000000000003'$q$);
SELECT tt.chk('T-27 Caller B memory remains unchanged',
 $q$SELECT claim='caller B secret' FROM memories WHERE id='c2740000-0000-0000-0000-000000000003'$q$);

-- The same Principal may resolve Caller B, but its context is isolated from A.
SELECT * FROM resolve_delegated_caller('c2720000-0000-0000-0000-000000000002');
SELECT tt.chk('T-27 Caller B sees its own episodic memory',
 $q$SELECT count(*)=1 FROM memories WHERE memory_kind='episodic'$q$);
SELECT tt.chk('T-27 Caller B cannot see Caller A episodic memory',
 $q$SELECT count(*)=0 FROM memories WHERE id='c2740000-0000-0000-0000-000000000001'$q$);
SELECT tt.chk('T-27 Caller B sees its own embedding only',
 $q$SELECT count(*)=1 FROM memory_embeddings$q$);
SELECT tt.chk('T-27 Caller B cannot see Caller A conflict edge',
 $q$SELECT count(*)=0 FROM memory_conflicts$q$);

COMMIT;
RESET ROLE;
SELECT tt.chk('T-27 Caller context does not leak after commit',
 $q$SELECT coalesce(current_setting('app.caller_id',true),'')=''$q$);
