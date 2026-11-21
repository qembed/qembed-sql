-- QSA-007: retention must never delete an outbox row with pending replay work.
\set ON_ERROR_STOP on
SET client_min_messages=warning;

INSERT INTO events(tenant_id,event_id,aggregate_type,aggregate_id,event_type,payload)
VALUES
 ('aaaaaaaa-0000-0000-0000-000000000001','31000000-0000-0000-0000-000000000002','qsa007','31000000-0000-0000-0000-000000000001','QSA007ReplayPending','{}'),
 ('aaaaaaaa-0000-0000-0000-000000000001','31000000-0000-0000-0000-000000000004','qsa007','31000000-0000-0000-0000-000000000003','QSA007RetentionEligible','{}');

INSERT INTO outbox_messages(
  tenant_id,delivery_id,event_id,topic,payload,created_at,delivered_at,
  replay_requested_at,replay_reason
)
VALUES
 ('aaaaaaaa-0000-0000-0000-000000000001','31000000-0000-0000-0000-000000000001',
  '31000000-0000-0000-0000-000000000002','qsa007.replay','{}',
  now()-interval '10 days',now()-interval '9 days',
  now()-interval '1 hour','invocation_progress_deadline_expired'),
 ('aaaaaaaa-0000-0000-0000-000000000001','31000000-0000-0000-0000-000000000003',
  '31000000-0000-0000-0000-000000000004','qsa007.retention','{}',
  now()-interval '10 days',now()-interval '9 days',NULL,NULL);

SET ROLE qembed_retention;
SELECT tt.chk('QSA-007 purge deletes only the eligible delivered row',
  $q$SELECT retention_purge('outbox_messages',now()-interval '1 day','QSA-007 replay safety')=1$q$);
RESET ROLE;

SELECT tt.chk('QSA-007 pending replay marker and delivery row survive retention',
  $q$SELECT count(*)=1
       FROM outbox_messages
      WHERE tenant_id='aaaaaaaa-0000-0000-0000-000000000001'
        AND delivery_id='31000000-0000-0000-0000-000000000001'
        AND replay_requested_at IS NOT NULL$q$);
SELECT tt.chk('QSA-007 old delivered row without pending replay is purged',
  $q$SELECT NOT EXISTS (
       SELECT 1 FROM outbox_messages
        WHERE tenant_id='aaaaaaaa-0000-0000-0000-000000000001'
          AND delivery_id='31000000-0000-0000-0000-000000000003')$q$);
SELECT tt.chk('QSA-007 retention log records exactly one deletion',
  $q$SELECT rows_affected=1 AND reason='QSA-007 replay safety'
       FROM retention_log WHERE table_name='outbox_messages'
       ORDER BY id DESC LIMIT 1$q$);
