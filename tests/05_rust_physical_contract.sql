-- AUDIT-001: physical contract against the Rust migrations
--   20261118000001_objects.sql, 20261118000002_snapshots.sql, 20261118000003_events_outbox.sql
-- Scope = the columns/keys AUDIT-001 aligns. Columns still open in later audits are NOT asserted here
-- (objects.state values -> AUDIT-003; snapshots.json_projection -> AUDIT-004;
--  events.aggregate_*/event_type, outbox_messages.topic/payload -> AUDIT-005).
\set ON_ERROR_STOP on
SET client_min_messages=warning;

SELECT tt.chk('AUDIT-001 Rust physical tables exist',
 $q$SELECT count(*)=5 FROM pg_class WHERE relnamespace='public'::regnamespace AND relkind='r'
      AND relname IN ('objects','object_versions','snapshots','events','outbox_messages')$q$);

SELECT tt.chk('AUDIT-001 r3 table names are gone',
 $q$SELECT count(*)=0 FROM pg_class WHERE relnamespace='public'::regnamespace AND relkind IN ('r','v','m')
      AND relname IN ('qembed_objects','runtime_snapshots','object_events','outbox')$q$);

SELECT tt.chk('AUDIT-001/004 column contract (type, NOT NULL, default) of Rust columns',
 $q$WITH want(t,c,ty,nn,def) AS (VALUES
   ('objects','tenant_id','uuid',true,NULL::text),
   ('objects','object_id','uuid',true,NULL),
   ('objects','published_version_id','uuid',false,NULL),
   ('objects','created_at','timestamp with time zone',true,'now()'),
   ('objects','state','text',true,'''draft''::text'),
   ('object_versions','tenant_id','uuid',true,NULL),
   ('object_versions','object_id','uuid',true,NULL),
   ('object_versions','object_version_id','uuid',true,NULL),
   ('object_versions','version_number','bigint',true,NULL),
   ('object_versions','status','text',true,'''draft''::text'),
   ('object_versions','created_at','timestamp with time zone',true,'now()'),
   ('snapshots','tenant_id','uuid',true,NULL),
   ('snapshots','snapshot_id','uuid',true,NULL),
   ('snapshots','object_id','uuid',true,NULL),
   ('snapshots','object_version_id','uuid',true,NULL),
   ('snapshots','schema_version','integer',true,NULL),
   ('snapshots','canonical_json','bytea',true,NULL),
   ('snapshots','content_hash','bytea',true,NULL),
   ('snapshots','json_projection','jsonb',true,NULL),
   ('snapshots','created_at','timestamp with time zone',true,'now()'),
   ('events','tenant_id','uuid',true,NULL),
   ('events','event_id','uuid',true,NULL),
   ('events','aggregate_type','text',true,NULL),
   ('events','aggregate_id','uuid',true,NULL),
   ('events','event_type','text',true,NULL),
   ('events','payload','jsonb',true,NULL),
   ('events','occurred_at','timestamp with time zone',true,'now()'),
   ('outbox_messages','tenant_id','uuid',true,NULL),
   ('outbox_messages','delivery_id','uuid',true,NULL),
   ('outbox_messages','event_id','uuid',true,NULL),
   ('outbox_messages','topic','text',true,NULL),
   ('outbox_messages','payload','jsonb',true,NULL),
   ('outbox_messages','created_at','timestamp with time zone',true,'now()'),
   ('outbox_messages','delivered_at','timestamp with time zone',false,NULL)
 ), have AS (
   SELECT c.relname t, a.attname c, format_type(a.atttypid,a.atttypmod) ty, a.attnotnull nn,
          pg_get_expr(d.adbin,d.adrelid) def
     FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid AND c.relnamespace='public'::regnamespace
     LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
    WHERE a.attnum>0 AND NOT a.attisdropped)
   SELECT count(*)=0 FROM want w LEFT JOIN have h USING (t,c)
    WHERE h.c IS NULL OR h.ty<>w.ty OR h.nn<>w.nn OR h.def IS DISTINCT FROM w.def$q$);

SELECT tt.chk('AUDIT-001 PK/UNIQUE/FK column lists match the Rust constraints',
 $q$WITH want(t,ty,cols,rt,rcols) AS (VALUES
   ('objects','p','tenant_id,object_id',NULL::text,NULL::text),
   ('objects','u','object_id',NULL,NULL),
   ('objects','f','tenant_id,object_id,published_version_id','object_versions','tenant_id,object_id,object_version_id'),
   ('object_versions','p','tenant_id,object_id,object_version_id',NULL,NULL),
   ('object_versions','u','object_version_id',NULL,NULL),
   ('object_versions','u','tenant_id,object_id,version_number',NULL,NULL),
   ('object_versions','f','tenant_id,object_id','objects','tenant_id,object_id'),
   ('snapshots','p','tenant_id,snapshot_id',NULL,NULL),
   ('snapshots','u','snapshot_id',NULL,NULL),
   ('snapshots','f','tenant_id,object_id,object_version_id','object_versions','tenant_id,object_id,object_version_id'),
   ('events','p','tenant_id,event_id',NULL,NULL),
   ('events','u','event_id',NULL,NULL),
   ('outbox_messages','p','tenant_id,delivery_id',NULL,NULL),
   ('outbox_messages','u','tenant_id,event_id',NULL,NULL),
   ('outbox_messages','f','tenant_id,event_id','events','tenant_id,event_id')
 ), have AS (
   SELECT c.relname t, k.contype::text ty,
     (SELECT string_agg(a.attname,',' ORDER BY x.ord) FROM unnest(k.conkey) WITH ORDINALITY x(n,ord)
        JOIN pg_attribute a ON a.attrelid=k.conrelid AND a.attnum=x.n) cols,
     r.relname rt,
     (SELECT string_agg(a.attname,',' ORDER BY x.ord) FROM unnest(k.confkey) WITH ORDINALITY x(n,ord)
        JOIN pg_attribute a ON a.attrelid=k.confrelid AND a.attnum=x.n) rcols
     FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid AND c.relnamespace='public'::regnamespace
     LEFT JOIN pg_class r ON r.oid=k.confrelid
    WHERE k.contype IN ('p','u','f'))
   SELECT count(*)=0 FROM want w WHERE NOT EXISTS (SELECT 1 FROM have h
     WHERE h.t=w.t AND h.ty=w.ty AND h.cols=w.cols AND h.rt IS NOT DISTINCT FROM w.rt AND h.rcols IS NOT DISTINCT FROM w.rcols)$q$);

SELECT tt.chk('AUDIT-001 Rust FKs are ON DELETE RESTRICT, published pointer FK keeps the Rust name',
 $q$SELECT (SELECT count(*)=4 FROM pg_constraint
             WHERE contype='f' AND confdeltype='r'
               AND conrelid::regclass::text||'->'||confrelid::regclass::text IN
                   ('objects->object_versions','object_versions->objects','snapshots->object_versions','outbox_messages->events'))
        AND EXISTS (SELECT 1 FROM pg_constraint WHERE conname='objects_published_version_fk')$q$);

SELECT tt.chk('AUDIT-001 objects has no FK to tenants (Rust path never creates tenant rows)',
 $q$SELECT count(*)=0 FROM pg_constraint WHERE contype='f' AND conrelid='objects'::regclass
      AND confrelid='tenants'::regclass$q$);

-- Probe with the Rust INSERT shape (no r3 payload columns). Rolled back via a sub-transaction so
-- fixtures of the later suites are untouched.
DO $$
DECLARE ok boolean := false; d text := '';
BEGIN
  BEGIN
    INSERT INTO objects(tenant_id,object_id,state)
      VALUES ('aaaaaaaa-0000-0000-0000-000000000001','0a1c0000-0000-0000-0000-000000000001','draft');
    INSERT INTO object_versions(tenant_id,object_id,object_version_id,version_number)
      VALUES ('aaaaaaaa-0000-0000-0000-000000000001','0a1c0000-0000-0000-0000-000000000001',
              '0a1c0000-0000-0000-0000-0000000000a1',1);
    ok := true;
    RAISE EXCEPTION 'probe-rollback';
  EXCEPTION WHEN others THEN
    IF SQLERRM <> 'probe-rollback' THEN ok := false; d := SQLSTATE||' '||left(SQLERRM,140); END IF;
  END;
  INSERT INTO tt.res VALUES ('AUDIT-001 Rust-shaped object + object_version INSERT accepted','true',ok::text,ok,d);
END $$;


-- AUDIT-003: Rust object state vocabulary/default and multiple concurrent Draft candidates.
SELECT tt.chk('AUDIT-003 no unique one-Draft-per-object index remains',
 $q$SELECT count(*)=0 FROM pg_indexes
    WHERE schemaname='public' AND tablename='object_versions'
      AND indexdef LIKE 'CREATE UNIQUE INDEX%WHERE (status = ''draft'')'$q$);

SELECT tt.try('AUDIT-003 legacy uppercase object state is rejected','err',
 $q$INSERT INTO objects(tenant_id,object_id,state)
    VALUES ('aaaaaaaa-0000-0000-0000-000000000001',gen_random_uuid(),'Draft')$q$);

DO $$
DECLARE object_state text; draft_count bigint; ok boolean := false; d text := '';
BEGIN
  BEGIN
    INSERT INTO objects(tenant_id,object_id)
      VALUES ('aaaaaaaa-0000-0000-0000-000000000001','0a1c0000-0000-0000-0000-000000000002')
      RETURNING state INTO object_state;
    INSERT INTO object_versions(tenant_id,object_id,object_version_id,version_number)
      VALUES
       ('aaaaaaaa-0000-0000-0000-000000000001','0a1c0000-0000-0000-0000-000000000002','0a1c0000-0000-0000-0000-0000000000a2',1),
       ('aaaaaaaa-0000-0000-0000-000000000001','0a1c0000-0000-0000-0000-000000000002','0a1c0000-0000-0000-0000-0000000000a3',2);
    SELECT count(*) INTO draft_count FROM object_versions
     WHERE tenant_id='aaaaaaaa-0000-0000-0000-000000000001'
       AND object_id='0a1c0000-0000-0000-0000-000000000002' AND status='draft';
    ok := object_state='draft' AND draft_count=2;
    RAISE EXCEPTION 'probe-rollback';
  EXCEPTION WHEN others THEN
    IF SQLERRM <> 'probe-rollback' THEN ok := false; d := SQLSTATE||' '||left(SQLERRM,140); END IF;
  END;
  INSERT INTO tt.res VALUES ('AUDIT-003 Rust default state and two Draft versions accepted','true',ok::text,ok,d);
END $$;
