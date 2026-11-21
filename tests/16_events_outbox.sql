-- AUDIT-005: events and transactional outbox match the Rust migration
\set ON_ERROR_STOP on
SET client_min_messages=warning;

SELECT tt.chk('AUDIT-005 events has exactly the Rust columns',
 $q$SELECT string_agg(attname, ',' ORDER BY attnum)
      = 'tenant_id,event_id,aggregate_type,aggregate_id,stream_version,event_type,payload,occurred_at'
    FROM pg_attribute WHERE attrelid='public.events'::regclass AND attnum>0 AND NOT attisdropped$q$);
SELECT tt.chk('AUDIT-005 outbox_messages has exactly the Rust columns',
 $q$SELECT string_agg(attname, ',' ORDER BY attnum)
      = 'tenant_id,delivery_id,event_id,topic,payload,created_at,delivered_at,publication_stream,publication_sequence,publication_duplicate,lease_owner,lease_expires_at,claim_token,attempts,replay_requested_at,replay_reason,replay_count'
    FROM pg_attribute WHERE attrelid='public.outbox_messages'::regclass AND attnum>0 AND NOT attisdropped$q$);
SELECT tt.chk('AUDIT-005 event aggregate ordering index exists',
 $q$SELECT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname='public'
   AND indexname='events_aggregate_order_idx'
   AND indexdef LIKE '%(tenant_id, aggregate_type, aggregate_id, stream_version)%')$q$);
SELECT tt.chk('T-29 unique monotonic event stream key exists',
 $q$SELECT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname='public'
   AND indexname='events_stream_version_unique'
   AND indexdef LIKE '%UNIQUE%' AND indexdef LIKE '%stream_version%')$q$);
SELECT tt.chk('T-29 event stream counter is tenant RLS protected',
 $q$SELECT relrowsecurity AND relforcerowsecurity FROM pg_class WHERE oid='public.event_stream_counters'::regclass$q$);

SELECT tt.chk('RUST-051a outbox lease fencing columns and defaults exist',
 $q$SELECT
   (SELECT column_default LIKE '%0%' FROM information_schema.columns
     WHERE table_schema='public' AND table_name='outbox_messages' AND column_name='claim_token')
   AND
   (SELECT column_default LIKE '%0%' FROM information_schema.columns
     WHERE table_schema='public' AND table_name='outbox_messages' AND column_name='attempts')
   AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='public.outbox_messages'::regclass
     AND conname='outbox_lease_pair')
   AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='public.outbox_messages'::regclass
     AND conname='outbox_delivered_unleased')$q$);

SELECT tt.chk('RUST-052c durable replay marker and index exist', 
 $q$SELECT
   EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='outbox_messages' AND column_name='replay_requested_at')
   AND EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='outbox_messages' AND column_name='replay_reason')
   AND EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='outbox_messages' AND column_name='replay_count' AND column_default LIKE '%0%')
   AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='public.outbox_messages'::regclass AND conname='outbox_replay_marker_pair')
   AND EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname='public' AND indexname='outbox_replay_requested_idx')
   AND to_regprocedure('public.sweep_stale_invocation_deliveries(timestamp with time zone,integer)') IS NOT NULL$q$);
SELECT tt.chk('RUST-052c replay function is callable by runtime but its mutation stays definer-owned',
 $q$SELECT has_function_privilege('qembed_runtime','public.sweep_stale_invocation_deliveries(timestamptz,integer)','EXECUTE')
   AND has_column_privilege('qembed_definer','public.outbox_messages','replay_requested_at','UPDATE')
   AND has_column_privilege('qembed_definer','public.object_invocations','heartbeat_at','UPDATE')
   AND has_column_privilege('qembed_dispatcher','public.outbox_messages','replay_requested_at','SELECT')
   AND has_column_privilege('qembed_dispatcher','public.outbox_messages','replay_requested_at','UPDATE')$q$);

SELECT tt.chk('RUST-051b publication receipt columns and consistency constraint exist',
 $q$SELECT
   EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='outbox_messages' AND column_name='publication_stream')
   AND EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='outbox_messages' AND column_name='publication_sequence')
   AND EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='outbox_messages' AND column_name='publication_duplicate')
   AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='public.outbox_messages'::regclass AND conname='outbox_publication_receipt_consistent')$q$);
SELECT tt.chk('RUST-051b dispatcher may read and write publication receipt only on Outbox',
 $q$SELECT
   has_column_privilege('qembed_dispatcher','public.outbox_messages','publication_stream','SELECT')
   AND has_column_privilege('qembed_dispatcher','public.outbox_messages','publication_sequence','SELECT')
   AND has_column_privilege('qembed_dispatcher','public.outbox_messages','publication_duplicate','SELECT')
   AND has_column_privilege('qembed_dispatcher','public.outbox_messages','publication_stream','UPDATE')
   AND has_column_privilege('qembed_dispatcher','public.outbox_messages','publication_sequence','UPDATE')
   AND has_column_privilege('qembed_dispatcher','public.outbox_messages','publication_duplicate','UPDATE')
   AND NOT has_column_privilege('qembed_dispatcher','public.outbox_messages','event_id','SELECT')
   AND NOT has_table_privilege('qembed_dispatcher','public.events','SELECT')$q$);

SELECT tt.chk('RUST-051b append-only publication receipt ledger exists',
 $q$SELECT
   to_regclass('public.outbox_publication_receipts') IS NOT NULL
   AND EXISTS (SELECT 1 FROM pg_class WHERE oid='public.outbox_publication_receipts'::regclass AND relrowsecurity AND relforcerowsecurity)
   AND EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid='public.outbox_publication_receipts'::regclass AND tgname='outbox_publication_receipts_append_only' AND NOT tgisinternal)$q$);
SELECT tt.chk('RUST-051b dispatcher can append but cannot inspect or mutate receipt history',
 $q$SELECT
   has_table_privilege('qembed_dispatcher','public.outbox_publication_receipts','INSERT')
   AND NOT has_table_privilege('qembed_dispatcher','public.outbox_publication_receipts','SELECT')
   AND NOT has_table_privilege('qembed_dispatcher','public.outbox_publication_receipts','UPDATE')
   AND NOT has_table_privilege('qembed_dispatcher','public.outbox_publication_receipts','DELETE')$q$);

SELECT tt.chk('AUDIT-005 pending outbox index matches delivered_at predicate',
 $q$SELECT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname='public'
   AND indexname='outbox_pending_idx'
   AND indexdef LIKE '%(created_at, delivery_id)%' AND indexdef LIKE '%WHERE (delivered_at IS NULL)%')$q$);

DO $$
DECLARE eid uuid := gen_random_uuid(); did uuid := gen_random_uuid();
        pending_eid uuid := gen_random_uuid(); pending_did uuid := gen_random_uuid();
        tid uuid := 'aaaaaaaa-0000-0000-0000-000000000001';
        got_state text; ok boolean := false;
BEGIN
  INSERT INTO events(tenant_id,event_id,aggregate_type,aggregate_id,event_type,payload)
    VALUES(tid,eid,'object','0b000000-0000-0000-0000-000000000001','object.created','{"v":1}');
  INSERT INTO outbox_messages(tenant_id,delivery_id,event_id,topic,payload)
    VALUES(tid,did,eid,'object.events','{"v":1}');
  INSERT INTO events(tenant_id,event_id,aggregate_type,aggregate_id,event_type,payload)
    VALUES(tid,pending_eid,'object','0b000000-0000-0000-0000-000000000001','object.updated','{"v":2}');
  INSERT INTO outbox_messages(tenant_id,delivery_id,event_id,topic,payload)
    VALUES(tid,pending_did,pending_eid,'object.events','{"v":2}');
  INSERT INTO tt.res VALUES ('AUDIT-005 Rust-shaped event and outbox inserts accepted','ok','ok',true,'');

  BEGIN
    UPDATE events SET payload='{"v":2}' WHERE tenant_id=tid AND event_id=eid;
    INSERT INTO tt.res VALUES ('AUDIT-005 event UPDATE rejected with 55000','55000','none',false,'update unexpectedly succeeded');
  EXCEPTION WHEN OTHERS THEN
    INSERT INTO tt.res VALUES ('AUDIT-005 event UPDATE rejected with 55000','55000',SQLSTATE,SQLSTATE='55000',SQLERRM);
  END;
  BEGIN
    DELETE FROM events WHERE tenant_id=tid AND event_id=eid;
    INSERT INTO tt.res VALUES ('AUDIT-005 event DELETE rejected with 55000','55000','none',false,'delete unexpectedly succeeded');
  EXCEPTION WHEN OTHERS THEN
    INSERT INTO tt.res VALUES ('AUDIT-005 event DELETE rejected with 55000','55000',SQLSTATE,SQLSTATE='55000',SQLERRM);
  END;
  BEGIN
    INSERT INTO outbox_messages(tenant_id,delivery_id,event_id,topic,payload)
      VALUES(tid,gen_random_uuid(),eid,'duplicate','{}');
    INSERT INTO tt.res VALUES ('AUDIT-005 one outbox row per tenant/event','unique violation','accepted',false,'duplicate event accepted');
  EXCEPTION WHEN unique_violation THEN
    INSERT INTO tt.res VALUES ('AUDIT-005 one outbox row per tenant/event','unique violation','unique violation',true,'');
  END;
  BEGIN
    INSERT INTO outbox_messages(tenant_id,delivery_id,event_id,topic,payload)
      VALUES(tid,gen_random_uuid(),gen_random_uuid(),'orphan','{}');
    INSERT INTO tt.res VALUES ('AUDIT-005 outbox requires matching tenant event','foreign key violation','accepted',false,'orphan event accepted');
  EXCEPTION WHEN foreign_key_violation THEN
    INSERT INTO tt.res VALUES ('AUDIT-005 outbox requires matching tenant event','foreign key violation','foreign key violation',true,'');
  END;
  -- Pending rows must remain undelivered; the dispatcher updates only delivered_at.
  UPDATE outbox_messages SET created_at=now()-interval '2 days'
    WHERE tenant_id=tid AND delivery_id IN (did,pending_did);
  UPDATE outbox_messages
    SET delivered_at=now(), publication_stream='QEMBED_EVENTS',
        publication_sequence=1, publication_duplicate=false
    WHERE tenant_id=tid AND delivery_id=did;
  INSERT INTO outbox_publication_receipts
    (tenant_id, delivery_id, publication_stream, publication_sequence, publication_duplicate)
  VALUES (tid, did, 'QEMBED_EVENTS', 1, false);

  BEGIN
    UPDATE outbox_publication_receipts SET publication_duplicate=true
      WHERE tenant_id=tid AND delivery_id=did;
    INSERT INTO tt.res VALUES ('RUST-051b PubAck history is immutable','55000','accepted',false,'receipt update unexpectedly accepted');
  EXCEPTION WHEN OTHERS THEN
    INSERT INTO tt.res VALUES ('RUST-051b PubAck history is immutable','55000',SQLSTATE,SQLSTATE='55000',SQLERRM);
  END;
  BEGIN
    UPDATE outbox_messages
      SET delivered_at=now(), publication_stream='QEMBED_EVENTS',
          publication_sequence=NULL, publication_duplicate=false
      WHERE tenant_id=tid AND delivery_id=pending_did;
    INSERT INTO tt.res VALUES ('RUST-051b partial PubAck receipt rejected','check violation','accepted',false,'partial receipt unexpectedly accepted');
  EXCEPTION WHEN check_violation THEN
    INSERT INTO tt.res VALUES ('RUST-051b partial PubAck receipt rejected','check violation','check violation',true,'');
  END;

  SELECT delivered_at IS NOT NULL INTO ok FROM outbox_messages WHERE tenant_id=tid AND delivery_id=did;
  INSERT INTO tt.res VALUES ('AUDIT-005 delivered_at marks successful delivery','true',ok::text,ok,'');
  INSERT INTO tt.res VALUES ('AUDIT-005 pending delivery remains undelivered','true',
    (SELECT (delivered_at IS NULL)::text FROM outbox_messages WHERE tenant_id=tid AND delivery_id=pending_did),
    EXISTS (SELECT 1 FROM outbox_messages WHERE tenant_id=tid AND delivery_id=pending_did AND delivered_at IS NULL),'');
END $$;
