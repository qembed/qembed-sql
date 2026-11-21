\set ON_ERROR_STOP on
SET client_min_messages=warning;
SET track_io_timing=on;

-- Preserve a true no-index baseline after the canonical schema adds this index.
DROP INDEX IF EXISTS idx_outbox_invocation_recovery;

-- QSA-022 controlled PG19 workload: 100k invocation.received outbox rows,
-- only two of which point to real stale invocations. The exact recovery join
-- matches payload->>'invocation_id' and the partial-index predicates.
INSERT INTO object_invocations
  (id, tenant_id, object_id, caller_id, snapshot_id, knowledge_revision,
   pool, status, trace_id, started_at)
VALUES
  (md5('qsa022-invocation-before')::uuid,
   'aaaaaaaa-0000-0000-0000-000000000001',
   '0b000000-0000-0000-0000-000000000001',
   'ca000000-0000-0000-0000-000000000001',
   '5a000000-0000-0000-0000-000000000001',
   0, 'authenticated', 'Received', gen_random_uuid(), now()-interval '2 hours'),
  (md5('qsa022-invocation-after')::uuid,
   'aaaaaaaa-0000-0000-0000-000000000001',
   '0b000000-0000-0000-0000-000000000001',
   'ca000000-0000-0000-0000-000000000001',
   '5a000000-0000-0000-0000-000000000001',
   0, 'authenticated', 'Received', gen_random_uuid(), now()-interval '1 hour');

INSERT INTO provider_call_attempts(tenant_id, object_id, invocation_id, state)
VALUES
  ('aaaaaaaa-0000-0000-0000-000000000001',
   '0b000000-0000-0000-0000-000000000001',
   md5('qsa022-invocation-before')::uuid, 'NotStarted'),
  ('aaaaaaaa-0000-0000-0000-000000000001',
   '0b000000-0000-0000-0000-000000000001',
   md5('qsa022-invocation-after')::uuid, 'NotStarted');

INSERT INTO events
  (tenant_id, event_id, aggregate_type, aggregate_id, stream_version, event_type, payload)
SELECT 'aaaaaaaa-0000-0000-0000-000000000001',
       md5('qsa022-event-' || n)::uuid,
       'qsa022-benchmark',
       md5('qsa022-aggregate-' || n)::uuid,
       NULL,
       'QSA022BenchmarkNoise',
       '{}'::jsonb
  FROM generate_series(1, 100000) AS n;

INSERT INTO outbox_messages
  (tenant_id, delivery_id, event_id, topic, payload, created_at, delivered_at)
SELECT 'aaaaaaaa-0000-0000-0000-000000000001',
       md5('qsa022-delivery-' || n)::uuid,
       md5('qsa022-event-' || n)::uuid,
       'invocation.received',
       jsonb_build_object(
         'invocation_id',
         CASE n
           WHEN 1 THEN md5('qsa022-invocation-before')::uuid::text
           WHEN 2 THEN md5('qsa022-invocation-after')::uuid::text
           ELSE md5('qsa022-unmatched-invocation-' || n)::uuid::text
         END
       ),
       now()-interval '1 hour',
       now()-interval '1 hour'
  FROM generate_series(1, 100000) AS n;

ANALYZE object_invocations;
ANALYZE provider_call_attempts;
ANALYZE outbox_messages;

\echo '=== QSA-022 BEFORE candidate index: exact stale-delivery recovery join ==='
EXPLAIN (ANALYZE, BUFFERS, SETTINGS)
SELECT invocation.id AS invocation_id, delivery.delivery_id
  FROM object_invocations AS invocation
  JOIN outbox_messages AS delivery
    ON delivery.tenant_id = invocation.tenant_id
   AND delivery.topic = 'invocation.received'
   AND delivery.payload->>'invocation_id' = invocation.id::text
 WHERE invocation.tenant_id = 'aaaaaaaa-0000-0000-0000-000000000001'
   AND invocation.status = 'Received'
   AND invocation.cancel_requested_at IS NULL
   AND (invocation.lease_owner IS NULL OR invocation.lease_until <= now())
   AND COALESCE(invocation.heartbeat_at, invocation.started_at) <= now()-interval '90 minutes'
   AND delivery.delivered_at IS NOT NULL
   AND delivery.replay_requested_at IS NULL
   AND (delivery.lease_expires_at IS NULL OR delivery.lease_expires_at <= now())
   AND EXISTS (
     SELECT 1
       FROM provider_call_attempts AS attempt
      WHERE attempt.tenant_id = invocation.tenant_id
        AND attempt.object_id = invocation.object_id
        AND attempt.invocation_id = invocation.id
        AND attempt.state IN ('NotStarted','ConfirmedNotAccepted','CancelledBeforeSend')
   )
 ORDER BY COALESCE(invocation.heartbeat_at, invocation.started_at), delivery.created_at
 LIMIT 1
 FOR UPDATE OF invocation, delivery SKIP LOCKED;

\echo '=== QSA-022 BEFORE candidate index: actual recovery function ==='
SET ROLE qembed_runtime;
SELECT set_config('app.tenant_id', 'aaaaaaaa-0000-0000-0000-000000000001', false);
EXPLAIN (ANALYZE, BUFFERS)
SELECT * FROM sweep_stale_invocation_deliveries(now()-interval '90 minutes', 1);
RESET ROLE;

CREATE INDEX qsa022_bench_outbox_invocation_idx
  ON outbox_messages (tenant_id, (payload->>'invocation_id'))
  WHERE topic = 'invocation.received'
    AND delivered_at IS NOT NULL
    AND replay_requested_at IS NULL;
ANALYZE outbox_messages;

SELECT pg_size_pretty(pg_relation_size('qsa022_bench_outbox_invocation_idx'))
  AS qsa022_candidate_index_size;

\echo '=== QSA-022 AFTER candidate index: exact stale-delivery recovery join ==='
EXPLAIN (ANALYZE, BUFFERS, SETTINGS)
SELECT invocation.id AS invocation_id, delivery.delivery_id
  FROM object_invocations AS invocation
  JOIN outbox_messages AS delivery
    ON delivery.tenant_id = invocation.tenant_id
   AND delivery.topic = 'invocation.received'
   AND delivery.payload->>'invocation_id' = invocation.id::text
 WHERE invocation.tenant_id = 'aaaaaaaa-0000-0000-0000-000000000001'
   AND invocation.status = 'Received'
   AND invocation.cancel_requested_at IS NULL
   AND (invocation.lease_owner IS NULL OR invocation.lease_until <= now())
   AND COALESCE(invocation.heartbeat_at, invocation.started_at) <= now()-interval '30 minutes'
   AND delivery.delivered_at IS NOT NULL
   AND delivery.replay_requested_at IS NULL
   AND (delivery.lease_expires_at IS NULL OR delivery.lease_expires_at <= now())
   AND EXISTS (
     SELECT 1
       FROM provider_call_attempts AS attempt
      WHERE attempt.tenant_id = invocation.tenant_id
        AND attempt.object_id = invocation.object_id
        AND attempt.invocation_id = invocation.id
        AND attempt.state IN ('NotStarted','ConfirmedNotAccepted','CancelledBeforeSend')
   )
 ORDER BY COALESCE(invocation.heartbeat_at, invocation.started_at), delivery.created_at
 LIMIT 1
 FOR UPDATE OF invocation, delivery SKIP LOCKED;

\echo '=== QSA-022 AFTER candidate index: actual recovery function ==='
SET ROLE qembed_runtime;
SELECT set_config('app.tenant_id', 'aaaaaaaa-0000-0000-0000-000000000001', false);
EXPLAIN (ANALYZE, BUFFERS)
SELECT * FROM sweep_stale_invocation_deliveries(now()-interval '30 minutes', 1);
RESET ROLE;
