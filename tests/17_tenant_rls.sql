-- AUDIT-006: tenant RLS is enforced on the actual Rust repository tables
\set ON_ERROR_STOP on
SET client_min_messages=warning;

-- Tenant B fixtures are inserted as the schema owner, before switching to runtime.
INSERT INTO objects(tenant_id,object_id,state)
VALUES ('bbbbbbbb-0000-0000-0000-000000000002','bb000000-0000-0000-0000-000000000001','draft');
INSERT INTO object_versions(tenant_id,object_id,object_version_id,version_number,status)
VALUES ('bbbbbbbb-0000-0000-0000-000000000002','bb000000-0000-0000-0000-000000000001',
        'bb000000-0000-0000-0000-000000000002',1,'draft');
DO $$
DECLARE raw bytea := convert_to('{"tenant":"B"}','UTF8');
BEGIN
  INSERT INTO snapshots(tenant_id,snapshot_id,object_id,object_version_id,schema_version,
                        canonical_json,content_hash,json_projection)
  VALUES ('bbbbbbbb-0000-0000-0000-000000000002','bb000000-0000-0000-0000-000000000003',
          'bb000000-0000-0000-0000-000000000001','bb000000-0000-0000-0000-000000000002',
          1,raw,digest(raw,'sha256'),convert_from(raw,'UTF8')::jsonb);
END $$;
INSERT INTO events(tenant_id,event_id,aggregate_type,aggregate_id,event_type,payload)
VALUES ('bbbbbbbb-0000-0000-0000-000000000002','bb000000-0000-0000-0000-000000000004',
        'object','bb000000-0000-0000-0000-000000000001','object.created','{}');
INSERT INTO outbox_messages(tenant_id,delivery_id,event_id,topic,payload)
VALUES ('bbbbbbbb-0000-0000-0000-000000000002','bb000000-0000-0000-0000-000000000005',
        'bb000000-0000-0000-0000-000000000004','object.created','{}');

-- Catalog audit: every NOT NULL tenant_id table is FORCE-RLS protected and has
-- the runtime tenant_isolation policy. Pre-auth owner_* tables are deliberately
-- excluded: Rust must look up credentials before a Scope exists; column grants
-- are their boundary (AUDIT-002).
SELECT tt.chk('AUDIT-006 all tenant-owned tables have ENABLE+FORCE RLS and runtime policy',
 $q$SELECT count(*)=0
    FROM pg_class c
    JOIN pg_namespace n ON n.oid=c.relnamespace
    JOIN pg_attribute a ON a.attrelid=c.oid AND a.attname='tenant_id' AND a.attnum>0 AND NOT a.attisdropped
   WHERE n.nspname='public' AND c.relkind IN ('r','p') AND a.attnotnull
     AND c.relname NOT IN ('owner_principals','owner_credentials')
     AND (NOT c.relrowsecurity OR NOT c.relforcerowsecurity OR NOT EXISTS (
       SELECT 1 FROM pg_policy p
       WHERE p.polrelid=c.oid AND p.polname='tenant_isolation'
         AND p.polroles @> ARRAY[(SELECT oid FROM pg_roles WHERE rolname='qembed_runtime')]::oid[]
         AND p.polcmd='*'
     ))$q$);

SELECT tt.chk('AUDIT-006 pre-auth owner tables remain outside tenant RLS',
 $q$SELECT bool_and(NOT c.relrowsecurity AND NOT c.relforcerowsecurity)
    FROM pg_class c WHERE c.oid IN ('public.owner_principals'::regclass,'public.owner_credentials'::regclass)$q$);

SET ROLE qembed_runtime;
SELECT set_config('app.tenant_id','aaaaaaaa-0000-0000-0000-000000000001',false);

-- Tenant A must not see the seeded tenant B rows in any Rust-backed table.
SELECT tt.chk('AUDIT-006 A cannot see B object', $q$SELECT count(*)=0 FROM objects WHERE object_id='bb000000-0000-0000-0000-000000000001'$q$);
SELECT tt.chk('AUDIT-006 A cannot see B object_version', $q$SELECT count(*)=0 FROM object_versions WHERE object_version_id='bb000000-0000-0000-0000-000000000002'$q$);
SELECT tt.chk('AUDIT-006 A cannot see B snapshot', $q$SELECT count(*)=0 FROM snapshots WHERE snapshot_id='bb000000-0000-0000-0000-000000000003'$q$);
SELECT tt.chk('AUDIT-006 A cannot see B event', $q$SELECT count(*)=0 FROM events WHERE event_id='bb000000-0000-0000-0000-000000000004'$q$);
SELECT tt.chk('AUDIT-006 A cannot see B outbox row', $q$SELECT count(*)=0 FROM outbox_messages WHERE delivery_id='bb000000-0000-0000-0000-000000000005'$q$);

-- A may see its own records already created by the Rust-shaped smoke suites.
SELECT tt.chk('AUDIT-006 A can see own object', $q$SELECT count(*)>=1 FROM objects WHERE object_id='0b000000-0000-0000-0000-000000000001'$q$);
SELECT tt.chk('AUDIT-006 A can see own version', $q$SELECT count(*)>=1 FROM object_versions WHERE object_id='0b000000-0000-0000-0000-000000000001'$q$);
SELECT tt.chk('AUDIT-006 A can see own snapshot', $q$SELECT count(*)>=1 FROM snapshots WHERE object_id='0b000000-0000-0000-0000-000000000001'$q$);
SELECT tt.chk('AUDIT-006 A can see own event', $q$SELECT count(*)>=1 FROM events WHERE aggregate_id='0b000000-0000-0000-0000-000000000001'$q$);
SELECT tt.chk('AUDIT-006 A can see own outbox row', $q$SELECT count(*)>=1 FROM outbox_messages$q$);

-- A cannot write a row tagged with B, and an unset tenant context sees no rows.
SELECT tt.try('AUDIT-006 A cannot insert object for B','err',$q$INSERT INTO objects(tenant_id,object_id,state) VALUES ('bbbbbbbb-0000-0000-0000-000000000002',gen_random_uuid(),'draft')$q$);
SELECT set_config('app.tenant_id','',false);
SELECT tt.chk('AUDIT-006 missing scope sees no Rust object rows', $q$SELECT count(*)=0 FROM objects$q$);
SELECT tt.chk('AUDIT-006 missing scope sees no Rust version rows', $q$SELECT count(*)=0 FROM object_versions$q$);
SELECT tt.chk('AUDIT-006 missing scope sees no Rust snapshot rows', $q$SELECT count(*)=0 FROM snapshots$q$);
SELECT tt.chk('AUDIT-006 missing scope sees no Rust event rows', $q$SELECT count(*)=0 FROM events$q$);
SELECT tt.chk('AUDIT-006 missing scope sees no Rust outbox rows', $q$SELECT count(*)=0 FROM outbox_messages$q$);
SELECT tt.try('AUDIT-006 missing scope cannot insert Rust event','err',$q$INSERT INTO events(tenant_id,event_id,aggregate_type,aggregate_id,event_type,payload) VALUES ('aaaaaaaa-0000-0000-0000-000000000001',gen_random_uuid(),'object','0b000000-0000-0000-0000-000000000001','no_scope','{}')$q$);

-- Switching the transaction-local context to B exposes B's own records only.
SELECT set_config('app.tenant_id','bbbbbbbb-0000-0000-0000-000000000002',false);
SELECT tt.chk('AUDIT-006 B can see own object', $q$SELECT count(*)=1 FROM objects WHERE object_id='bb000000-0000-0000-0000-000000000001'$q$);
SELECT tt.chk('AUDIT-006 B can see own version', $q$SELECT count(*)=1 FROM object_versions WHERE object_version_id='bb000000-0000-0000-0000-000000000002'$q$);
SELECT tt.chk('AUDIT-006 B can see own snapshot', $q$SELECT count(*)=1 FROM snapshots WHERE snapshot_id='bb000000-0000-0000-0000-000000000003'$q$);
SELECT tt.chk('AUDIT-006 B can see own event', $q$SELECT count(*)=1 FROM events WHERE event_id='bb000000-0000-0000-0000-000000000004'$q$);
SELECT tt.chk('AUDIT-006 B can see own outbox row', $q$SELECT count(*)=1 FROM outbox_messages WHERE delivery_id='bb000000-0000-0000-0000-000000000005'$q$);
RESET ROLE;
