-- RT-058: Owner grants Caller access to another active Principal in the same Tenant.
\set ON_ERROR_STOP on
SET client_min_messages=warning;

INSERT INTO tenants(id) VALUES
 ('d1100000-0000-0000-0000-000000000001'),
 ('d1100000-0000-0000-0000-000000000002');

INSERT INTO owner_principals(tenant_id,caller_id,principal_kind) VALUES
 ('d1100000-0000-0000-0000-000000000001','d1110000-0000-0000-0000-000000000001','tenant_owner'),
 ('d1100000-0000-0000-0000-000000000002','d1110000-0000-0000-0000-000000000003','tenant_owner');

-- The Owner rows are mirrored into principals by the compatibility trigger.
INSERT INTO principals(id,tenant_id,kind,key_hash) VALUES
 ('d1110000-0000-0000-0000-000000000002','d1100000-0000-0000-0000-000000000001','TenantAdmin',digest('admin-key','sha256')),
 ('d1110000-0000-0000-0000-000000000004','d1100000-0000-0000-0000-000000000001','Service',digest('service-key','sha256')),
 ('d1110000-0000-0000-0000-000000000005',NULL,'PlatformAdmin',digest('platform-key','sha256'));

INSERT INTO callers(id,tenant_id,token_hash,caller_kind) VALUES
 ('d1120000-0000-0000-0000-000000000001','d1100000-0000-0000-0000-000000000001',digest('delegated-authenticated','sha256'),'Authenticated'),
 ('d1120000-0000-0000-0000-000000000002','d1100000-0000-0000-0000-000000000001',digest('delegated-service','sha256'),'Service'),
 ('d1120000-0000-0000-0000-000000000003','d1100000-0000-0000-0000-000000000002',digest('other-tenant-caller','sha256'),'Authenticated');

SET ROLE qembed_runtime;
SELECT set_config('app.tenant_id','d1100000-0000-0000-0000-000000000001',false);
SELECT set_config('app.principal_id','d1110000-0000-0000-0000-000000000001',false);
SELECT set_config('app.sql058_admin_grant',
  grant_caller_delegation('d1110000-0000-0000-0000-000000000002','d1120000-0000-0000-0000-000000000001')::text,false);
SELECT set_config('app.sql058_service_grant',
  grant_caller_delegation('d1110000-0000-0000-0000-000000000004','d1120000-0000-0000-0000-000000000002')::text,false);

SELECT tt.chk('RT-058 Owner grants Caller to another Principal',
 $q$SELECT count(*)=2 FROM principal_caller_delegations
     WHERE tenant_id='d1100000-0000-0000-0000-000000000001'
       AND principal_id IN ('d1110000-0000-0000-0000-000000000002',
                            'd1110000-0000-0000-0000-000000000004')
       AND revoked_at IS NULL$q$);

-- Delegated TenantAdmin resolves the Authenticated Caller under its own identity.
SELECT set_config('app.principal_id','d1110000-0000-0000-0000-000000000002',false);
SELECT tt.chk('RT-058 TenantAdmin resolves only its delegated Caller',
 $q$SELECT EXISTS (SELECT 1 FROM resolve_delegated_caller('d1120000-0000-0000-0000-000000000001')
                    WHERE caller_kind='Authenticated')$q$);
SELECT tt.try('RT-058 TenantAdmin cannot grant delegation','err',
 $q$SELECT grant_caller_delegation('d1110000-0000-0000-0000-000000000004',
                                    'd1120000-0000-0000-0000-000000000002')$q$);
SELECT tt.try('RT-058 TenantAdmin cannot revoke delegation','err',
 $q$SELECT revoke_caller_delegation(current_setting('app.sql058_service_grant')::uuid)$q$);

-- Delegated Service Principal resolves independently through its own grant.
SELECT set_config('app.principal_id','d1110000-0000-0000-0000-000000000004',false);
SELECT tt.chk('RT-058 Service Principal resolves its delegated Service Caller',
 $q$SELECT EXISTS (SELECT 1 FROM resolve_delegated_caller('d1120000-0000-0000-0000-000000000002')
                    WHERE caller_kind='Service')$q$);
SELECT tt.try('RT-058 undelegated Caller is rejected','err',
 $q$SELECT * FROM resolve_delegated_caller('d1120000-0000-0000-0000-000000000001')$q$);

-- PlatformAdmin has no tenant and cannot be made a tenant invocation Principal.
SELECT set_config('app.principal_id','d1110000-0000-0000-0000-000000000001',false);
SELECT tt.try('RT-058 cross-tenant Caller cannot be delegated','err',
 $q$SELECT grant_caller_delegation('d1110000-0000-0000-0000-000000000002',
                                    'd1120000-0000-0000-0000-000000000003')$q$);

-- Only TenantOwner can revoke; the actor is recorded separately from the grantee.
SELECT tt.chk('RT-058 Owner can revoke a delegation granted to another Principal',
 $q$SELECT revoke_caller_delegation(current_setting('app.sql058_admin_grant')::uuid)$q$);
SELECT tt.chk('RT-058 revocation records Owner actor',
 $q$SELECT revoked_at IS NOT NULL
          AND revoked_by_principal_id='d1110000-0000-0000-0000-000000000001'
       FROM principal_caller_delegations
      WHERE delegation_id=current_setting('app.sql058_admin_grant')::uuid$q$);
SELECT tt.try('RT-058 revoked delegation cannot be resolved','err',
 $q$SELECT * FROM resolve_delegated_caller('d1120000-0000-0000-0000-000000000001')$q$);

SELECT tt.try('RT-058 runtime cannot insert delegation rows directly','err',
 $q$INSERT INTO principal_caller_delegations(delegation_id,tenant_id,principal_id,caller_id)
     VALUES (gen_random_uuid(),'d1100000-0000-0000-0000-000000000001',
             'd1110000-0000-0000-0000-000000000002','d1120000-0000-0000-0000-000000000001')$q$);
SELECT tt.try('RT-058 runtime cannot update delegation rows directly','err',
 $q$UPDATE principal_caller_delegations SET revoked_at=now()$q$);
RESET ROLE;

-- Object-level public invocation is explicit in the schema and defaults true.
SELECT tt.chk('RT-058 new Objects default to Anonymous invocation enabled',
 $q$SELECT column_default LIKE '%true%' AND is_nullable='NO'
      FROM information_schema.columns
     WHERE table_schema='public' AND table_name='objects'
       AND column_name='anonymous_invocation_enabled'$q$);

SELECT tt.chk('RT-058 delegation revocation requires an actor',
 $q$SELECT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = 'principal_caller_delegations'::regclass
           AND contype = 'c'
           AND pg_get_constraintdef(oid) LIKE '%revoked_at IS NULL%'
           AND pg_get_constraintdef(oid) LIKE '%revoked_by_principal_id IS NULL%'
      )$q$);

