-- RUST-041d: provider-call attempt state and conservative reservation expiry.
\set A '''aaaaaaaa-0000-0000-0000-000000000001'''
SET client_min_messages=warning;
SET ROLE qembed_runtime;
SELECT set_config('app.tenant_id', :A, false) \gset

SELECT tt.chk('RUST-041d reservation creates a NotStarted provider attempt',
  $q$SELECT state='NotStarted' AND input_tokens IS NULL AND output_tokens IS NULL
       FROM provider_call_attempts
      WHERE tenant_id=current_setting('app.tenant_id')::uuid
        AND invocation_id='1a000000-0000-0000-0000-000000000001'$q$);

SELECT tt.try('RUST-041d mark possible provider send', 'ok', $q$
  UPDATE provider_call_attempts SET state='MayHaveBeenSent', updated_at=now()
   WHERE tenant_id=current_setting('app.tenant_id')::uuid
     AND invocation_id='1a000000-0000-0000-0000-000000000001'
$q$);
SELECT tt.try('RUST-041d record ambiguous provider outcome', 'ok', $q$
  UPDATE provider_call_attempts SET state='OutcomeUnknown', updated_at=now()
   WHERE tenant_id=current_setting('app.tenant_id')::uuid
     AND invocation_id='1a000000-0000-0000-0000-000000000001'
$q$);
SELECT tt.try('RUST-041d ambiguous outcome cannot be reset to NotStarted', 'err', $q$
  UPDATE provider_call_attempts SET state='NotStarted'
   WHERE tenant_id=current_setting('app.tenant_id')::uuid
     AND invocation_id='1a000000-0000-0000-0000-000000000001'
$q$);
SELECT tt.try('RUST-041d expiry sweeper executes with ambiguous reservation present', 'ok', $q$
  SELECT sweep_expired_reservations(100)
$q$);
SELECT tt.chk('RUST-041d sweeper retains possibly-sent reservation',
  $q$SELECT br.status='Reserved' AND pca.state='OutcomeUnknown'
       FROM budget_reservations br
       JOIN provider_call_attempts pca USING (tenant_id,object_id,invocation_id)
      WHERE br.tenant_id=current_setting('app.tenant_id')::uuid
        AND br.invocation_id='1a000000-0000-0000-0000-000000000001'$q$);

SELECT tt.try('RUST-041d unknown outcome may reconcile to durable response', 'ok', $q$
  UPDATE provider_call_attempts
     SET state='ResponseReceived', input_tokens=12, output_tokens=7, updated_at=now()
   WHERE tenant_id=current_setting('app.tenant_id')::uuid
     AND invocation_id='1a000000-0000-0000-0000-000000000001'
$q$);
SELECT tt.try('RUST-041d persisted response usage is immutable', 'err', $q$
  UPDATE provider_call_attempts SET input_tokens=13
   WHERE tenant_id=current_setting('app.tenant_id')::uuid
     AND invocation_id='1a000000-0000-0000-0000-000000000001'
$q$);


SELECT tt.try('RUST-041d seed a second invocation for pre-send cancellation', 'ok', $q$
  INSERT INTO object_invocations
    (id,tenant_id,object_id,caller_id,snapshot_id,knowledge_revision,pool,status,trace_id)
  VALUES
    ('1a000000-0000-0000-0000-00000000000c',
     current_setting('app.tenant_id')::uuid,
     '0b000000-0000-0000-0000-000000000001',
     'ca000000-0000-0000-0000-000000000001',
     '5a000000-0000-0000-0000-000000000001',
     0,'authenticated','Received',gen_random_uuid())
$q$);
SELECT tt.try('RUST-041d create its expired reservation', 'ok', $q$
  INSERT INTO budget_reservations
    (id,tenant_id,object_id,invocation_id,pool,usage_date,reserved_tokens,
     reserved_cost_micros,status,expires_at)
  VALUES
    ('b1000000-0000-0000-0000-00000000000c',
     current_setting('app.tenant_id')::uuid,
     '0b000000-0000-0000-0000-000000000001',
     '1a000000-0000-0000-0000-00000000000c',
     'authenticated',current_date,25,0,'Reserved',now()-interval '1 minute')
$q$);
SELECT tt.try('RUST-041d cancellation before send is durable', 'ok', $q$
  UPDATE provider_call_attempts
     SET state='CancelledBeforeSend', updated_at=now()
   WHERE tenant_id=current_setting('app.tenant_id')::uuid
     AND invocation_id='1a000000-0000-0000-0000-00000000000c'
$q$);
SELECT tt.try('RUST-041d sweeper expires a cancelled-before-send reservation', 'ok', $q$
  SELECT sweep_expired_reservations(100)
$q$);
SELECT tt.chk('RUST-041d pre-send cancellation releases only its reservation',
  $q$SELECT br.status='Expired' AND pca.state='CancelledBeforeSend'
       FROM budget_reservations br
       JOIN provider_call_attempts pca USING (tenant_id,object_id,invocation_id)
      WHERE br.tenant_id=current_setting('app.tenant_id')::uuid
        AND br.invocation_id='1a000000-0000-0000-0000-00000000000c'$q$);

RESET ROLE;
