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
RESET ROLE;
SET ROLE qembed_worker;
SELECT tt.try('RUST-041d worker expiry sweeper executes with ambiguous reservation present', 'ok', $q$
  SELECT sweep_expired_reservations(100)
$q$);
RESET ROLE;
SET ROLE qembed_runtime;
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
SELECT tt.try('RUST-041d settle response and release its reservation atomically', 'ok', $q$
  UPDATE budget_reservations
     SET status='Settled', actual_tokens=19, actual_cost_micros=0
   WHERE tenant_id=current_setting('app.tenant_id')::uuid
     AND invocation_id='1a000000-0000-0000-0000-000000000001'
     AND status='Reserved';
  UPDATE usage_counters
     SET reserved_tokens=reserved_tokens-500,
         reserved_cost_micros=reserved_cost_micros-500,
         consumed_tokens=consumed_tokens+19
   WHERE tenant_id=current_setting('app.tenant_id')::uuid
     AND object_id='0b000000-0000-0000-0000-000000000001'
     AND usage_date=current_date AND pool='authenticated';
  UPDATE caller_usage_counters
     SET reserved_tokens=reserved_tokens-500, consumed_tokens=consumed_tokens+19
   WHERE tenant_id=current_setting('app.tenant_id')::uuid
     AND object_id='0b000000-0000-0000-0000-000000000001'
     AND caller_id='ca000000-0000-0000-0000-000000000001'
     AND usage_date=current_date
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
SELECT tt.try('RUST-041d reserve usage for second invocation', 'ok', $q$
  UPDATE usage_counters SET reserved_tokens=reserved_tokens+25,
       reserved_cost_micros=reserved_cost_micros+7
   WHERE tenant_id=current_setting('app.tenant_id')::uuid
     AND object_id='0b000000-0000-0000-0000-000000000001'
     AND usage_date=current_date AND pool='authenticated';
  UPDATE caller_usage_counters SET reserved_tokens=reserved_tokens+25
   WHERE tenant_id=current_setting('app.tenant_id')::uuid
     AND object_id='0b000000-0000-0000-0000-000000000001'
     AND caller_id='ca000000-0000-0000-0000-000000000001'
     AND usage_date=current_date;
  INSERT INTO budget_reservations
    (id,tenant_id,object_id,invocation_id,pool,usage_date,reserved_tokens,
     reserved_cost_micros,status,expires_at)
  VALUES
    ('b1000000-0000-0000-0000-00000000000c',
     current_setting('app.tenant_id')::uuid,
     '0b000000-0000-0000-0000-000000000001',
     '1a000000-0000-0000-0000-00000000000c',
     'authenticated',current_date,25,7,'Reserved','2026-01-02 00:00:00+00')
$q$);
SELECT tt.try('RUST-041d cancellation before send is durable', 'ok', $q$
  UPDATE provider_call_attempts
     SET state='CancelledBeforeSend', updated_at=now()
   WHERE tenant_id=current_setting('app.tenant_id')::uuid
     AND invocation_id='1a000000-0000-0000-0000-00000000000c'
$q$);
-- Simulate accounting drift: the reservation still exists, but aggregate counters
-- are lower than its release amount. The sweeper must not abort the batch.
UPDATE usage_counters SET reserved_tokens=0, reserved_cost_micros=0
 WHERE tenant_id=current_setting('app.tenant_id')::uuid
   AND object_id='0b000000-0000-0000-0000-000000000001'
   AND usage_date=current_date AND pool='authenticated';
UPDATE caller_usage_counters SET reserved_tokens=0
 WHERE tenant_id=current_setting('app.tenant_id')::uuid
   AND object_id='0b000000-0000-0000-0000-000000000001'
   AND caller_id='ca000000-0000-0000-0000-000000000001'
   AND usage_date=current_date;
RESET ROLE;
SET ROLE qembed_worker;
SELECT tt.chk('RUST-062 reservation before deterministic cutoff is retained',
  $q$SELECT sweep_expired_reservations(100, '2026-01-01 00:00:00+00'::timestamptz)=0$q$);
SELECT tt.chk('RUST-062 worker sweeper expires eligible reservation without aborting on counter drift',
  $q$SELECT sweep_expired_reservations(100, '2026-01-03 00:00:00+00'::timestamptz)=1$q$);
SELECT tt.chk('RUST-062 repeated sweep does not release counters twice',
  $q$SELECT sweep_expired_reservations(100, '2026-01-03 00:00:00+00'::timestamptz)=0$q$);
RESET ROLE;
SET ROLE qembed_runtime;
SELECT tt.chk('RUST-041d pre-send cancellation releases only its reservation',
  $q$SELECT br.status='Expired' AND pca.state='CancelledBeforeSend'
       FROM budget_reservations br
       JOIN provider_call_attempts pca USING (tenant_id,object_id,invocation_id)
      WHERE br.tenant_id=current_setting('app.tenant_id')::uuid
        AND br.invocation_id='1a000000-0000-0000-0000-00000000000c'$q$);
SELECT tt.chk('QSA-010 counter drift clamps aggregate and Caller counters at zero',
  $q$SELECT u.reserved_tokens=0 AND u.reserved_cost_micros=0 AND c.reserved_tokens=0
       FROM usage_counters u JOIN caller_usage_counters c
         ON c.tenant_id=u.tenant_id AND c.object_id=u.object_id AND c.usage_date=u.usage_date
      WHERE u.tenant_id=current_setting('app.tenant_id')::uuid
        AND u.object_id='0b000000-0000-0000-0000-000000000001'
        AND u.usage_date=current_date AND u.pool='authenticated'
        AND c.caller_id='ca000000-0000-0000-0000-000000000001'$q$);

RESET ROLE;
