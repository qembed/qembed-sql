-- AUDIT-008: composite foreign keys must preserve tenant identity
\set ON_ERROR_STOP on
SET client_min_messages=warning;

-- Catalog-wide invariant: whenever a tenant-scoped child references a
-- tenant-scoped parent, the FK must pair child.tenant_id with parent.tenant_id.
SELECT tt.chk('AUDIT-008 every FK to a tenant-owned table carries tenant_id',
 $q$SELECT count(*)=0
   FROM pg_constraint fk
   JOIN pg_class child ON child.oid=fk.conrelid
   JOIN pg_namespace cn ON cn.oid=child.relnamespace AND cn.nspname='public'
   JOIN pg_class parent ON parent.oid=fk.confrelid
   JOIN pg_namespace pn ON pn.oid=parent.relnamespace AND pn.nspname='public'
   JOIN pg_attribute parent_tenant
     ON parent_tenant.attrelid=parent.oid AND parent_tenant.attname='tenant_id'
    AND parent_tenant.attnum>0 AND NOT parent_tenant.attisdropped AND parent_tenant.attnotnull
   JOIN pg_attribute child_tenant
     ON child_tenant.attrelid=child.oid AND child_tenant.attname='tenant_id'
    AND child_tenant.attnum>0 AND NOT child_tenant.attisdropped
  WHERE fk.contype='f'
    AND NOT EXISTS (
      SELECT 1
        FROM unnest(fk.conkey) WITH ORDINALITY src(attnum,ord)
        JOIN unnest(fk.confkey) WITH ORDINALITY dst(attnum,ord) USING (ord)
        JOIN pg_attribute sa ON sa.attrelid=child.oid AND sa.attnum=src.attnum
        JOIN pg_attribute da ON da.attrelid=parent.oid AND da.attnum=dst.attnum
       WHERE sa.attname='tenant_id' AND da.attname='tenant_id'
    )$q$);

-- Seed a second-tenant object/version and event. The UUIDs are isolated to this suite.
INSERT INTO objects(tenant_id,object_id,state)
VALUES ('bbbbbbbb-0000-0000-0000-000000000002',
        '19000000-0000-0000-0000-000000000001','draft');
INSERT INTO object_versions(tenant_id,object_id,object_version_id,version_number,status)
VALUES ('bbbbbbbb-0000-0000-0000-000000000002',
        '19000000-0000-0000-0000-000000000001',
        '19000000-0000-0000-0000-000000000002',1,'draft');
INSERT INTO events(tenant_id,event_id,aggregate_type,aggregate_id,event_type,payload)
VALUES ('bbbbbbbb-0000-0000-0000-000000000002',
        '19000000-0000-0000-0000-000000000003','object',
        '19000000-0000-0000-0000-000000000001','audit.fixture','{}');

SELECT tt.try('AUDIT-008 object_version cannot attach to another tenant object','err',
 $q$INSERT INTO object_versions(tenant_id,object_id,object_version_id,version_number,status)
    VALUES ('aaaaaaaa-0000-0000-0000-000000000001',
            '19000000-0000-0000-0000-000000000001',
            '19000000-0000-0000-0000-000000000004',1,'draft')$q$);

SELECT tt.try('AUDIT-008 snapshot cannot reference another tenant version','err',
 $q$INSERT INTO snapshots(tenant_id,snapshot_id,object_id,object_version_id,schema_version,canonical_json,content_hash,json_projection)
    VALUES ('aaaaaaaa-0000-0000-0000-000000000001',
            '19000000-0000-0000-0000-000000000005',
            '19000000-0000-0000-0000-000000000001',
            '19000000-0000-0000-0000-000000000002',
            1,convert_to('{}','UTF8'),digest(convert_to('{}','UTF8'),'sha256'),'{}'::jsonb)$q$);

SELECT tt.try('AUDIT-008 outbox cannot reference another tenant event','err',
 $q$INSERT INTO outbox_messages(tenant_id,delivery_id,event_id,topic,payload)
    VALUES ('aaaaaaaa-0000-0000-0000-000000000001',
            '19000000-0000-0000-0000-000000000006',
            '19000000-0000-0000-0000-000000000003','audit.fixture','{}')$q$);

INSERT INTO owner_principals(tenant_id,caller_id,principal_kind)
VALUES ('bbbbbbbb-0000-0000-0000-000000000002',
        '19000000-0000-0000-0000-000000000007','tenant_owner');
SELECT tt.try('AUDIT-008 owner credential cannot cross tenant principal boundary','err',
 $q$INSERT INTO owner_credentials(tenant_id,caller_id,token_hash)
    VALUES ('aaaaaaaa-0000-0000-0000-000000000001',
            '19000000-0000-0000-0000-000000000007',
            decode(repeat('19',32),'hex'))$q$);

-- The composite published pointer must also bind tenant AND object identity.
INSERT INTO objects(tenant_id,object_id,state)
VALUES ('aaaaaaaa-0000-0000-0000-000000000001',
        '19000000-0000-0000-0000-000000000008','draft');
UPDATE objects SET state='validating'
 WHERE tenant_id='aaaaaaaa-0000-0000-0000-000000000001'
   AND object_id='19000000-0000-0000-0000-000000000008';
SELECT tt.try('AUDIT-008 published pointer cannot target another tenant version','err',
 $q$DO $audit$
    BEGIN
      SET CONSTRAINTS objects_published_version_fk IMMEDIATE;
      UPDATE objects SET state='active',
        published_version_id='19000000-0000-0000-0000-000000000002'
       WHERE tenant_id='aaaaaaaa-0000-0000-0000-000000000001'
         AND object_id='19000000-0000-0000-0000-000000000008';
    END
   $audit$q$);
