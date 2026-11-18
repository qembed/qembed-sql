-- AUDIT-005: events and transactional outbox match the Rust migration
\set ON_ERROR_STOP on
SET client_min_messages=warning;

SELECT tt.chk('AUDIT-005 events has exactly the Rust columns',
 $q$SELECT string_agg(attname, ',' ORDER BY attnum)
      = 'tenant_id,event_id,aggregate_type,aggregate_id,event_type,payload,occurred_at'
    FROM pg_attribute WHERE attrelid='public.events'::regclass AND attnum>0 AND NOT attisdropped$q$);
SELECT tt.chk('AUDIT-005 outbox_messages has exactly the Rust columns',
 $q$SELECT string_agg(attname, ',' ORDER BY attnum)
      = 'tenant_id,delivery_id,event_id,topic,payload,created_at,delivered_at'
    FROM pg_attribute WHERE attrelid='public.outbox_messages'::regclass AND attnum>0 AND NOT attisdropped$q$);
SELECT tt.chk('AUDIT-005 event aggregate ordering index exists',
 $q$SELECT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname='public'
   AND indexname='events_aggregate_order_idx'
   AND indexdef LIKE '%(tenant_id, aggregate_type, aggregate_id, occurred_at, event_id)%')$q$);
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
  UPDATE outbox_messages SET delivered_at=now()
    WHERE tenant_id=tid AND delivery_id=did;
  SELECT delivered_at IS NOT NULL INTO ok FROM outbox_messages WHERE tenant_id=tid AND delivery_id=did;
  INSERT INTO tt.res VALUES ('AUDIT-005 delivered_at marks successful delivery','true',ok::text,ok,'');
  INSERT INTO tt.res VALUES ('AUDIT-005 pending delivery remains undelivered','true',
    (SELECT (delivered_at IS NULL)::text FROM outbox_messages WHERE tenant_id=tid AND delivery_id=pending_did),
    EXISTS (SELECT 1 FROM outbox_messages WHERE tenant_id=tid AND delivery_id=pending_did AND delivered_at IS NULL),'');
END $$;
