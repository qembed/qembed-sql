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

-- RUST-052c: verify the durable replay schema as a physical contract, not by names alone.
SELECT tt.chk('RUST-052c replay columns have exact types and nullability',
 $q$SELECT array_agg(attname || ':' || format_type(atttypid,atttypmod) || ':' || attnotnull::text ORDER BY attname)
      = ARRAY[
        'replay_count:integer:true',
        'replay_reason:text:false',
        'replay_requested_at:timestamp with time zone:false'
      ]::text[]
    FROM pg_attribute
   WHERE attrelid='public.outbox_messages'::regclass
     AND attnum>0 AND NOT attisdropped
     AND attname IN ('replay_requested_at','replay_reason','replay_count')$q$);

SELECT tt.chk('RUST-052c replay_count default is exactly zero',
 $q$SELECT pg_get_expr(d.adbin,d.adrelid)='0'
      FROM pg_attrdef d
      JOIN pg_attribute a ON a.attrelid=d.adrelid AND a.attnum=d.adnum
     WHERE d.adrelid='public.outbox_messages'::regclass
       AND a.attname='replay_count'$q$);

SELECT tt.chk('RUST-052c replay marker constraint is validated and exact',
 $q$SELECT convalidated
        AND regexp_replace(pg_get_constraintdef(oid), '\\s+', ' ', 'g')
          = 'CHECK (((replay_requested_at IS NULL) AND (replay_reason IS NULL)) OR ((replay_requested_at IS NOT NULL) AND (replay_reason = ''invocation_progress_deadline_expired''::text) AND (delivered_at IS NOT NULL)))'
      FROM pg_constraint
     WHERE conrelid='public.outbox_messages'::regclass
       AND conname='outbox_replay_marker_pair'$q$);

SELECT tt.chk('RUST-052c replay index has exact keys, predicate and is valid',
 $q$SELECT i.indisvalid AND i.indisready AND NOT i.indisunique
        AND pg_get_expr(i.indpred,i.indrelid)='(replay_requested_at IS NOT NULL)'
        AND pg_get_indexdef(i.indexrelid)
          = 'CREATE INDEX outbox_replay_requested_idx ON public.outbox_messages USING btree (replay_requested_at, created_at, delivery_id) WHERE (replay_requested_at IS NOT NULL)'
      FROM pg_index i
     WHERE i.indexrelid=to_regclass('public.outbox_replay_requested_idx')
       AND i.indrelid='public.outbox_messages'::regclass$q$);

SELECT tt.chk('RUST-052c recovery function is hardened SECURITY DEFINER',
 $q$SELECT p.prosecdef
        AND pg_get_userbyid(p.proowner)='qembed_definer'
        AND p.proconfig @> ARRAY['search_path=pg_catalog, public, pg_temp']
        AND NOT has_function_privilege('public',p.oid,'EXECUTE')
      FROM pg_proc p
     WHERE p.oid=to_regprocedure('public.sweep_stale_invocation_deliveries(timestamptz,integer)')$q$);

SELECT tt.chk('RUST-052c runtime alone can invoke the recovery function',
 $q$SELECT has_function_privilege('qembed_runtime',f,'EXECUTE')
        AND NOT has_function_privilege('qembed_retention',f,'EXECUTE')
        AND NOT has_function_privilege('qembed_admin',f,'EXECUTE')
        AND NOT has_function_privilege('qembed_dispatcher',f,'EXECUTE')
        AND NOT has_function_privilege('public',f,'EXECUTE')
      FROM (SELECT 'public.sweep_stale_invocation_deliveries(timestamptz,integer)'::regprocedure AS f) fn$q$);

SELECT tt.chk('RUST-052c replay mutation privileges are split by responsibility',
 $q$SELECT
        has_column_privilege('qembed_definer','public.outbox_messages','replay_requested_at','UPDATE')
        AND has_column_privilege('qembed_definer','public.outbox_messages','replay_reason','UPDATE')
        AND has_column_privilege('qembed_definer','public.outbox_messages','replay_count','UPDATE')
        AND has_column_privilege('qembed_definer','public.object_invocations','heartbeat_at','UPDATE')
        AND NOT has_column_privilege('qembed_runtime','public.outbox_messages','replay_requested_at','UPDATE')
        AND has_column_privilege('qembed_dispatcher','public.outbox_messages','replay_requested_at','SELECT')
        AND has_column_privilege('qembed_dispatcher','public.outbox_messages','replay_reason','SELECT')
        AND has_column_privilege('qembed_dispatcher','public.outbox_messages','replay_count','SELECT')
        AND has_column_privilege('qembed_dispatcher','public.outbox_messages','replay_requested_at','UPDATE')
        AND has_column_privilege('qembed_dispatcher','public.outbox_messages','replay_reason','UPDATE')
        AND NOT has_column_privilege('qembed_dispatcher','public.outbox_messages','replay_count','UPDATE')$q$);

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
