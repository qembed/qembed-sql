-- AUDIT-002: owner authentication against the Rust model
--   Rust: 20261118000000_owner_authentication.sql + qembed-store/src/auth.rs
\set ON_ERROR_STOP on
SET client_min_messages=warning;

-- ---- contract: exact column set (no extra/secret columns), types, NOT NULL, defaults ----
SELECT tt.chk('AUDIT-002 owner_principals columns = Rust columns',
 $q$SELECT string_agg(a.attname||':'||format_type(a.atttypid,a.atttypmod)||':'||a.attnotnull||':'||coalesce(pg_get_expr(d.adbin,d.adrelid),''), ',' ORDER BY a.attnum)
      = 'tenant_id:uuid:true:,caller_id:uuid:true:,principal_kind:text:true:,disabled_at:timestamp with time zone:false:,created_at:timestamp with time zone:true:now()'
    FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
   WHERE a.attrelid='public.owner_principals'::regclass AND a.attnum>0 AND NOT a.attisdropped$q$);
SELECT tt.chk('AUDIT-002 owner_credentials columns = Rust columns',
 $q$SELECT string_agg(a.attname||':'||format_type(a.atttypid,a.atttypmod)||':'||a.attnotnull||':'||coalesce(pg_get_expr(d.adbin,d.adrelid),''), ',' ORDER BY a.attnum)
      = 'tenant_id:uuid:true:,caller_id:uuid:true:,token_hash:bytea:true:,revoked_at:timestamp with time zone:false:,created_at:timestamp with time zone:true:now()'
    FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
   WHERE a.attrelid='public.owner_credentials'::regclass AND a.attnum>0 AND NOT a.attisdropped$q$);
SELECT tt.chk('AUDIT-002 PK/FK shape (credential PK incl. digest; FK -> principal RESTRICT)',
 $q$SELECT (SELECT array_agg(a.attname ORDER BY x.o) FROM pg_constraint k CROSS JOIN LATERAL unnest(k.conkey) WITH ORDINALITY x(n,o)
             JOIN pg_attribute a ON a.attrelid=k.conrelid AND a.attnum=x.n
            WHERE k.conrelid='owner_principals'::regclass AND k.contype='p') = ARRAY['tenant_id','caller_id']::name[]
       AND (SELECT array_agg(a.attname ORDER BY x.o) FROM pg_constraint k CROSS JOIN LATERAL unnest(k.conkey) WITH ORDINALITY x(n,o)
             JOIN pg_attribute a ON a.attrelid=k.conrelid AND a.attnum=x.n
            WHERE k.conrelid='owner_credentials'::regclass AND k.contype='p') = ARRAY['tenant_id','caller_id','token_hash']::name[]
       AND EXISTS (SELECT 1 FROM pg_constraint k WHERE k.conrelid='owner_credentials'::regclass AND k.contype='f'
            AND k.confrelid='owner_principals'::regclass AND k.confdeltype='r'
            AND (SELECT array_agg(a.attname ORDER BY x.o) FROM unnest(k.conkey) WITH ORDINALITY x(n,o)
                  JOIN pg_attribute a ON a.attrelid=k.conrelid AND a.attnum=x.n) = ARRAY['tenant_id','caller_id']::name[])$q$);
SELECT tt.chk('AUDIT-002 owner_credentials_active_lookup is UNIQUE (tenant_id, token_hash) WHERE revoked_at IS NULL',
 $q$SELECT indexdef LIKE 'CREATE UNIQUE INDEX owner_credentials_active_lookup ON public.owner_credentials%(tenant_id, token_hash) WHERE (revoked_at IS NULL)'
    FROM pg_indexes WHERE indexname='owner_credentials_active_lookup'$q$);

-- ---- fixtures (superuser) ----
-- tenant A: P1 active (tok-a1), P2 disabled (tok-a2), P3 active principal with revoked credential (tok-a3); tenant B: P4 (tok-b4)
INSERT INTO owner_principals(tenant_id,caller_id,principal_kind,disabled_at) VALUES
 ('aaaaaaaa-0000-0000-0000-000000000001','c1000000-0000-0000-0000-000000000001','tenant_owner',NULL),
 ('aaaaaaaa-0000-0000-0000-000000000001','c1000000-0000-0000-0000-000000000002','tenant_owner',now()),
 ('aaaaaaaa-0000-0000-0000-000000000001','c1000000-0000-0000-0000-000000000003','tenant_owner',NULL),
 ('bbbbbbbb-0000-0000-0000-000000000002','c1000000-0000-0000-0000-000000000004','tenant_owner',NULL);
INSERT INTO owner_credentials(tenant_id,caller_id,token_hash,revoked_at) VALUES
 ('aaaaaaaa-0000-0000-0000-000000000001','c1000000-0000-0000-0000-000000000001',digest('tok-a1','sha256'),NULL),
 ('aaaaaaaa-0000-0000-0000-000000000001','c1000000-0000-0000-0000-000000000002',digest('tok-a2','sha256'),NULL),
 ('aaaaaaaa-0000-0000-0000-000000000001','c1000000-0000-0000-0000-000000000003',digest('tok-a3','sha256'),now()),
 ('bbbbbbbb-0000-0000-0000-000000000002','c1000000-0000-0000-0000-000000000004',digest('tok-b4','sha256'),NULL);

-- The exact query of OwnerAuthenticator::authenticate (auth.rs), parameterised; SECURITY INVOKER,
-- so it runs with the privileges of whichever role calls it.
CREATE OR REPLACE FUNCTION tt.owner_lookup(p_tenant uuid, p_token text) RETURNS text
LANGUAGE sql AS $$
  SELECT principal.tenant_id::text || '/' || principal.caller_id::text
  FROM owner_principals AS principal
  INNER JOIN owner_credentials AS credential
      ON credential.tenant_id = principal.tenant_id
      AND credential.caller_id = principal.caller_id
  WHERE principal.tenant_id = p_tenant
      AND credential.token_hash = digest(p_token, 'sha256')
      AND principal.principal_kind = 'tenant_owner'
      AND principal.disabled_at IS NULL
      AND credential.revoked_at IS NULL
$$;
GRANT EXECUTE ON FUNCTION tt.owner_lookup(uuid,text) TO PUBLIC;

-- ---- lookup under the application role WITHOUT tenant context (pre-auth) ----
SET ROLE qembed_runtime;
SELECT set_config('app.tenant_id','',false);
SELECT tt.chk('AUDIT-002 pre-auth lookup works without tenant context (valid token -> its principal)',
 $q$SELECT tt.owner_lookup('aaaaaaaa-0000-0000-0000-000000000001','tok-a1') = 'aaaaaaaa-0000-0000-0000-000000000001/c1000000-0000-0000-0000-000000000001'$q$);
SELECT tt.chk('AUDIT-002 tenant B token resolves in tenant B',
 $q$SELECT tt.owner_lookup('bbbbbbbb-0000-0000-0000-000000000002','tok-b4') = 'bbbbbbbb-0000-0000-0000-000000000002/c1000000-0000-0000-0000-000000000004'$q$);
SELECT tt.chk('AUDIT-002 revoked credential does not authenticate',
 $q$SELECT tt.owner_lookup('aaaaaaaa-0000-0000-0000-000000000001','tok-a3') IS NULL$q$);
SELECT tt.chk('AUDIT-002 disabled principal does not authenticate',
 $q$SELECT tt.owner_lookup('aaaaaaaa-0000-0000-0000-000000000001','tok-a2') IS NULL$q$);
SELECT tt.chk('AUDIT-002 tenant-mismatched token does not authenticate',
 $q$SELECT tt.owner_lookup('bbbbbbbb-0000-0000-0000-000000000002','tok-a1') IS NULL$q$);
SELECT tt.chk('AUDIT-002 unknown token does not authenticate',
 $q$SELECT tt.owner_lookup('aaaaaaaa-0000-0000-0000-000000000001','nope') IS NULL$q$);
-- least privilege of the application role on the auth tables
SELECT tt.try('AUDIT-002 runtime cannot INSERT principal','err',$q$INSERT INTO owner_principals(tenant_id,caller_id,principal_kind) VALUES (gen_random_uuid(),gen_random_uuid(),'tenant_owner')$q$);
SELECT tt.try('AUDIT-002 runtime cannot INSERT credential','err',$q$INSERT INTO owner_credentials(tenant_id,caller_id,token_hash) VALUES ('aaaaaaaa-0000-0000-0000-000000000001','c1000000-0000-0000-0000-000000000001',digest('x','sha256'))$q$);
SELECT tt.try('AUDIT-002 runtime cannot revoke (UPDATE)','err',$q$UPDATE owner_credentials SET revoked_at=now()$q$);
SELECT tt.try('AUDIT-002 runtime cannot DELETE','err',$q$DELETE FROM owner_credentials$q$);
SELECT tt.try('AUDIT-002 runtime cannot read non-lookup columns (created_at)','err',$q$SELECT created_at FROM owner_credentials$q$);
RESET ROLE;
SET ROLE qembed_dispatcher;
SELECT tt.try('AUDIT-002 dispatcher cannot read credentials','err',$q$SELECT token_hash FROM owner_credentials$q$);
RESET ROLE;

-- ---- integrity (superuser; every negative case must fail on the intended constraint) ----
SELECT tt.chk('AUDIT-002 raw token is not stored (digest only, 32 bytes)',
 $q$SELECT count(*)=0 FROM owner_credentials WHERE token_hash = convert_to('tok-a1','UTF8') OR octet_length(token_hash)<>32$q$);
SELECT tt.try('AUDIT-002 principal_kind other than tenant_owner denied','err',$q$INSERT INTO owner_principals(tenant_id,caller_id,principal_kind) VALUES (gen_random_uuid(),gen_random_uuid(),'tenant_admin')$q$);
SELECT tt.try('AUDIT-002 digest of wrong length denied','err',$q$INSERT INTO owner_credentials(tenant_id,caller_id,token_hash) VALUES ('aaaaaaaa-0000-0000-0000-000000000001','c1000000-0000-0000-0000-000000000001','\x0102')$q$);
SELECT tt.try('AUDIT-002 credential without principal denied (FK)','err',$q$INSERT INTO owner_credentials(tenant_id,caller_id,token_hash) VALUES ('aaaaaaaa-0000-0000-0000-000000000001',gen_random_uuid(),digest('orphan','sha256'))$q$);
SELECT tt.try('AUDIT-002 credential in another tenant than its principal denied (FK)','err',$q$INSERT INTO owner_credentials(tenant_id,caller_id,token_hash) VALUES ('bbbbbbbb-0000-0000-0000-000000000002','c1000000-0000-0000-0000-000000000001',digest('xt','sha256'))$q$);
SELECT tt.try('AUDIT-002 DELETE principal that has credentials denied (RESTRICT)','err',$q$DELETE FROM owner_principals WHERE caller_id='c1000000-0000-0000-0000-000000000001'$q$);
SELECT tt.try('AUDIT-002 second ACTIVE credential with the same digest in a tenant denied','err',$q$INSERT INTO owner_credentials(tenant_id,caller_id,token_hash) VALUES ('aaaaaaaa-0000-0000-0000-000000000001','c1000000-0000-0000-0000-000000000003',digest('tok-a1','sha256'))$q$);
SELECT tt.try('AUDIT-002 un-revoke denied (revocation is final)','err',$q$UPDATE owner_credentials SET revoked_at=NULL WHERE token_hash=digest('tok-a3','sha256')$q$);
SELECT tt.try('AUDIT-002 digest change denied','err',$q$UPDATE owner_credentials SET token_hash=digest('other','sha256') WHERE token_hash=digest('tok-a1','sha256')$q$);

-- ---- admin lifecycle: provision, re-issue over a revoked digest, revoke, disable ----
SET ROLE qembed_admin;
SELECT tt.try('AUDIT-002 admin provisions principal','ok',$q$INSERT INTO owner_principals(tenant_id,caller_id,principal_kind) VALUES ('bbbbbbbb-0000-0000-0000-000000000002','c1000000-0000-0000-0000-000000000005','tenant_owner')$q$);
SELECT tt.try('AUDIT-002 admin re-issues a digest whose old credential is revoked','ok',$q$INSERT INTO owner_credentials(tenant_id,caller_id,token_hash) VALUES ('aaaaaaaa-0000-0000-0000-000000000001','c1000000-0000-0000-0000-000000000001',digest('tok-a3','sha256'))$q$);
SELECT tt.try('AUDIT-002 admin revokes credential','ok',$q$UPDATE owner_credentials SET revoked_at=now() WHERE token_hash=digest('tok-a1','sha256')$q$);
SELECT tt.try('AUDIT-002 admin disables principal','ok',$q$UPDATE owner_principals SET disabled_at=now() WHERE caller_id='c1000000-0000-0000-0000-000000000004'$q$);
SELECT tt.try('AUDIT-002 admin cannot UPDATE principal identity','err',$q$UPDATE owner_principals SET caller_id=caller_id WHERE caller_id='c1000000-0000-0000-0000-000000000004'$q$);
SELECT tt.try('AUDIT-002 admin cannot UPDATE principal kind','err',$q$UPDATE owner_principals SET principal_kind='tenant_owner' WHERE caller_id='c1000000-0000-0000-0000-000000000004'$q$);
SELECT tt.try('AUDIT-002 admin cannot DELETE credential','err',$q$DELETE FROM owner_credentials$q$);
RESET ROLE;
SET ROLE qembed_runtime;
SELECT tt.chk('AUDIT-002 re-issued digest authenticates its new principal',
 $q$SELECT tt.owner_lookup('aaaaaaaa-0000-0000-0000-000000000001','tok-a3') = 'aaaaaaaa-0000-0000-0000-000000000001/c1000000-0000-0000-0000-000000000001'$q$);
SELECT tt.chk('AUDIT-002 credential revoked by admin stops authenticating',
 $q$SELECT tt.owner_lookup('aaaaaaaa-0000-0000-0000-000000000001','tok-a1') IS NULL$q$);
SELECT tt.chk('AUDIT-002 principal disabled by admin stops authenticating',
 $q$SELECT tt.owner_lookup('bbbbbbbb-0000-0000-0000-000000000002','tok-b4') IS NULL$q$);
RESET ROLE;
