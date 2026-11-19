-- RUST-041d: provider-call attempt state and conservative reservation expiry.
\\set A '''aaaaaaaa-0000-0000-0000-000000000001'''
SET client_min_messages=warning;
SET ROLE qembed_runtime;
SELECT set_config('app.tenant_id', :A, false) \\gset

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

RESET ROLE;
