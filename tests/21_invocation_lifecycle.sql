-- AUDIT-009: Invocation state machine, optimistic version and lease fencing.
\set A '''aaaaaaaa-0000-0000-0000-000000000001'''
SET client_min_messages=warning;
SET ROLE qembed_runtime;
SELECT set_config('app.tenant_id', :A, false) \gset

SELECT tt.try('AUDIT-009 new invocation must start Received', 'err', $q$
  INSERT INTO object_invocations
    (id,tenant_id,object_id,caller_id,snapshot_id,knowledge_revision,pool,status,trace_id)
  VALUES
    ('1a000000-0000-0000-0000-000000000009',
     current_setting('app.tenant_id')::uuid,
     '0b000000-0000-0000-0000-000000000001',
     'ca000000-0000-0000-0000-000000000001',
     '5a000000-0000-0000-0000-000000000001',
     0,'authenticated','Processing',gen_random_uuid())
$q$);

SELECT tt.try('AUDIT-009 reject skipped Received -> Processing', 'err', $q$
  UPDATE object_invocations SET status='Processing', version=version+1
   WHERE id='1a000000-0000-0000-0000-000000000001'
$q$);

SELECT tt.try('AUDIT-009 initial lease claim keeps initial fencing token', 'ok', $q$
  UPDATE object_invocations
     SET lease_owner='worker-a', lease_until=now()+interval '1 minute', heartbeat_at=now()
   WHERE id='1a000000-0000-0000-0000-000000000001'
$q$);
SELECT tt.chk('AUDIT-009 initial claim leaves version/token unchanged',
  $q$SELECT version=0 AND fencing_token=0 AND lease_owner='worker-a'
        FROM object_invocations WHERE id='1a000000-0000-0000-0000-000000000001'$q$);

SELECT tt.try('AUDIT-009 heartbeat does not advance optimistic version', 'ok', $q$
  UPDATE object_invocations
     SET lease_until=now()+interval '2 minutes', heartbeat_at=now()
   WHERE id='1a000000-0000-0000-0000-000000000001'
$q$);
SELECT tt.chk('AUDIT-009 heartbeat preserves version/token',
  $q$SELECT version=0 AND fencing_token=0 FROM object_invocations
       WHERE id='1a000000-0000-0000-0000-000000000001'$q$);

SELECT tt.try('AUDIT-009 active lease cannot be stolen', 'err', $q$
  UPDATE object_invocations
     SET lease_owner='worker-b', lease_until=now()+interval '2 minutes'
   WHERE id='1a000000-0000-0000-0000-000000000001'
$q$);
SELECT tt.try('AUDIT-009 fencing token cannot advance before lease expiry', 'err', $q$
  UPDATE object_invocations
     SET fencing_token=1, version=version+1,
         lease_owner='worker-b', lease_until=now()+interval '1 minute'
   WHERE id='1a000000-0000-0000-0000-000000000001'
$q$);

SELECT tt.try('AUDIT-009 expire old lease for reclaim fixture', 'ok', $q$
  UPDATE object_invocations SET lease_until=now()-interval '1 second'
   WHERE id='1a000000-0000-0000-0000-000000000001'
$q$);
SELECT tt.try('AUDIT-009 expired lease cannot be renewed without fencing', 'err', $q$
  UPDATE object_invocations
     SET lease_until=now()+interval '1 minute', heartbeat_at=now()
   WHERE id='1a000000-0000-0000-0000-000000000001'
$q$);
SELECT tt.try('AUDIT-009 reclaim advances fencing token and version', 'ok', $q$
  UPDATE object_invocations
     SET fencing_token=1, version=version+1,
         lease_owner='worker-b', lease_until=now()+interval '1 minute', heartbeat_at=now()
   WHERE id='1a000000-0000-0000-0000-000000000001'
$q$);
SELECT tt.chk('AUDIT-009 reclaim installs token 1 and version 1',
  $q$SELECT version=1 AND fencing_token=1 AND lease_owner='worker-b'
        FROM object_invocations WHERE id='1a000000-0000-0000-0000-000000000001'$q$);

SELECT tt.try('AUDIT-009 stale worker token rejected', 'err', $q$
  UPDATE object_invocations
     SET status='ContextLoading', fencing_token=0, version=version+1
   WHERE id='1a000000-0000-0000-0000-000000000001'
$q$);
SELECT tt.try('AUDIT-009 identity mutation rejected', 'err', $q$
  UPDATE object_invocations SET snapshot_id='5a000000-0000-0000-0000-000000000002'
   WHERE id='1a000000-0000-0000-0000-000000000001'
$q$);

SELECT tt.try('AUDIT-009 Received -> ContextLoading', 'ok', $q$
  UPDATE object_invocations SET status='ContextLoading', version=version+1
   WHERE id='1a000000-0000-0000-0000-000000000001'
$q$);
SELECT tt.try('AUDIT-009 version must advance on state transition', 'err', $q$
  UPDATE object_invocations SET status='Processing'
   WHERE id='1a000000-0000-0000-0000-000000000001'
$q$);
SELECT tt.try('AUDIT-009 ContextLoading -> Processing', 'ok', $q$
  UPDATE object_invocations SET status='Processing', version=version+1
   WHERE id='1a000000-0000-0000-0000-000000000001'
$q$);
SELECT tt.try('AUDIT-009 Processing cannot skip directly to Verifying', 'err', $q$
  UPDATE object_invocations SET status='Verifying', version=version+1
   WHERE id='1a000000-0000-0000-0000-000000000001'
$q$);
SELECT tt.try('AUDIT-009 Processing -> ExecutingTool', 'ok', $q$
  UPDATE object_invocations SET status='ExecutingTool', version=version+1
   WHERE id='1a000000-0000-0000-0000-000000000001'
$q$);
SELECT tt.try('AUDIT-009 ExecutingTool -> Processing', 'ok', $q$
  UPDATE object_invocations SET status='Processing', version=version+1
   WHERE id='1a000000-0000-0000-0000-000000000001'
$q$);
SELECT tt.try('AUDIT-009 Processing -> Verifying', 'ok', $q$
  UPDATE object_invocations SET status='Verifying', version=version+1
   WHERE id='1a000000-0000-0000-0000-000000000001'
$q$);
SELECT tt.try('AUDIT-009 Verifying -> Completed', 'ok', $q$
  UPDATE object_invocations
     SET status='Completed', version=version+1, finished_at=now(),
         lease_owner=NULL, lease_until=NULL
   WHERE id='1a000000-0000-0000-0000-000000000001'
$q$);
SELECT tt.chk('AUDIT-009 terminal invocation has final version and cleared lease',
  $q$SELECT status='Completed' AND version=7 AND fencing_token=1
              AND finished_at IS NOT NULL AND lease_owner IS NULL AND lease_until IS NULL
        FROM object_invocations WHERE id='1a000000-0000-0000-0000-000000000001'$q$);
SELECT tt.try('AUDIT-009 terminal invocation cannot be reopened', 'err', $q$
  UPDATE object_invocations SET status='Processing', version=version+1
   WHERE id='1a000000-0000-0000-0000-000000000001'
$q$);

RESET ROLE;
