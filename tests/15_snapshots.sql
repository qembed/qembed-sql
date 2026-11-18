-- AUDIT-004: snapshots match the Rust physical and behavioral contract
-- Rust: 20261118000002_snapshots.sql, snapshot_repository.rs, domain snapshot.rs
\set ON_ERROR_STOP on
SET client_min_messages=warning;

SELECT tt.chk('AUDIT-004 snapshots has exactly the Rust columns',
 $q$SELECT string_agg(a.attname, ',' ORDER BY a.attnum)
      = 'tenant_id,snapshot_id,object_id,object_version_id,schema_version,canonical_json,content_hash,json_projection,created_at'
    FROM pg_attribute a
   WHERE a.attrelid='public.snapshots'::regclass AND a.attnum>0 AND NOT a.attisdropped$q$);

SELECT tt.chk('AUDIT-004 canonical_json BYTEA, content_hash BYTEA(32), json_projection JSONB are required',
 $q$SELECT
   (SELECT atttypid='bytea'::regtype AND attnotnull FROM pg_attribute WHERE attrelid='public.snapshots'::regclass AND attname='canonical_json')
   AND (SELECT atttypid='bytea'::regtype AND attnotnull FROM pg_attribute WHERE attrelid='public.snapshots'::regclass AND attname='content_hash')
   AND (SELECT atttypid='jsonb'::regtype AND attnotnull FROM pg_attribute WHERE attrelid='public.snapshots'::regclass AND attname='json_projection')
   AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='public.snapshots'::regclass AND contype='c'
     AND pg_get_constraintdef(oid) LIKE '%octet_length(content_hash) = 32%')$q$);

DO $$
DECLARE sid uuid := gen_random_uuid(); raw bytea := convert_to('{"a":1,"z":0}','UTF8');
        stored bytea; h bytea; projection jsonb; ok boolean := false;
BEGIN
  INSERT INTO snapshots(tenant_id,snapshot_id,object_id,object_version_id,schema_version,canonical_json,content_hash,json_projection)
  VALUES ('aaaaaaaa-0000-0000-0000-000000000001',sid,
          '0b000000-0000-0000-0000-000000000001','0c000000-0000-0000-0000-000000000001',
          1,raw,digest(raw,'sha256'),convert_from(raw,'UTF8')::jsonb);
  SELECT canonical_json,content_hash,json_projection INTO stored,h,projection
    FROM snapshots WHERE tenant_id='aaaaaaaa-0000-0000-0000-000000000001' AND snapshot_id=sid;
  ok := stored=raw AND h=digest(raw,'sha256') AND projection='{"a":1,"z":0}'::jsonb
        AND projection::text <> convert_from(raw,'UTF8');
  INSERT INTO tt.res VALUES ('AUDIT-004 exact source bytes and derived JSONB projection preserved','true',ok::text,ok,'');
  -- Rust verifies digest and RFC 8785 form on read; the DB only enforces digest length.
  INSERT INTO snapshots(tenant_id,snapshot_id,object_id,object_version_id,schema_version,canonical_json,content_hash,json_projection)
  VALUES ('aaaaaaaa-0000-0000-0000-000000000001',gen_random_uuid(),
          '0b000000-0000-0000-0000-000000000001','0c000000-0000-0000-0000-000000000001',
          1,raw,decode(repeat('00',32),'hex'),convert_from(raw,'UTF8')::jsonb);
  INSERT INTO tt.res VALUES ('AUDIT-004 DB leaves hash verification to Rust read boundary','accepted','accepted',true,'');
  BEGIN
    INSERT INTO snapshots(tenant_id,snapshot_id,object_id,object_version_id,schema_version,canonical_json,content_hash,json_projection)
    VALUES ('aaaaaaaa-0000-0000-0000-000000000001',gen_random_uuid(),
            '0b000000-0000-0000-0000-000000000001','0c000000-0000-0000-0000-000000000001',
            1,raw,digest(raw,'sha256'),'{"a":999}'::jsonb);
    INSERT INTO tt.res VALUES ('AUDIT-004 mismatched projection rejected with 23514','23514','none',false,'insert unexpectedly succeeded');
  EXCEPTION WHEN OTHERS THEN
    INSERT INTO tt.res VALUES ('AUDIT-004 mismatched projection rejected with 23514','23514',SQLSTATE,SQLSTATE='23514',SQLERRM);
  END;
  BEGIN
    UPDATE snapshots SET canonical_json=convert_to('{"tampered":true}','UTF8')
     WHERE tenant_id='aaaaaaaa-0000-0000-0000-000000000001' AND snapshot_id=sid;
    INSERT INTO tt.res VALUES ('AUDIT-004 snapshot UPDATE rejected with 55000','55000','none',false,'update unexpectedly succeeded');
  EXCEPTION WHEN OTHERS THEN
    INSERT INTO tt.res VALUES ('AUDIT-004 snapshot UPDATE rejected with 55000','55000',SQLSTATE,SQLSTATE='55000',SQLERRM);
  END;
  BEGIN
    DELETE FROM snapshots WHERE tenant_id='aaaaaaaa-0000-0000-0000-000000000001' AND snapshot_id=sid;
    INSERT INTO tt.res VALUES ('AUDIT-004 snapshot DELETE rejected with 55000','55000','none',false,'delete unexpectedly succeeded');
  EXCEPTION WHEN OTHERS THEN
    INSERT INTO tt.res VALUES ('AUDIT-004 snapshot DELETE rejected with 55000','55000',SQLSTATE,SQLSTATE='55000',SQLERRM);
  END;
END $$;
