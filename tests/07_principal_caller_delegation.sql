-- SQL-011: Principal -> Caller delegation contract.
-- The authenticated application transaction sets app.tenant_id and app.principal_id
-- from the verified OwnerAuthenticator result; clients never supply either context.
\set ON_ERROR_STOP on
SET client_min_messages=warning;

INSERT INTO tenants(id) VALUES
 ('d1100000-0000-0000-0000-000000000001'),
 ('d1100000-0000-0000-0000-000000000002');

INSERT INTO owner_principals(tenant_id,caller_id,principal_kind) VALUES
 ('d1100000-0000-0000-0000-000000000001','d1110000-0000-0000-0000-000000000001','tenant_owner'),
 ('d1100000-0000-0000-0000-000000000001','d1110000-0000-0000-0000-000000000002','tenant_owner'),
 ('d1100000-0000-0000-0000-000000000002','d1110000-0000-0000-0000-000000000003','tenant_owner');

INSERT INTO callers(id,tenant_id,token_hash,caller_kind) VALUES
 ('d1120000-0000-0000-0000-000000000001','d1100000-0000-0000-0000-000000000001',digest('delegated-authenticated','sha256'),'Authenticated'),
 ('d1120000-0000-0000-0000-000000000002','d1100000-0000-0000-0000-000000000001',digest('delegated-service','sha256'),'Service'),
 ('d1120000-0000-0000-0000-000000000003','d1100000-0000-0000-0000-000000000001',digest('delegated-anonymous','sha256'),'Anonymous'),
 ('d1120000-0000-0000-0000-000000000004','d1100000-0000-0000-0000-000000000002',digest('other-tenant-caller','sha256'),'Authenticated');

-- A principal may act as multiple active Caller kinds; mapping is tenant-scoped.
SET ROLE qembed_runtime;
SELECT set_config('app.tenant_id','d1100000-0000-0000-0000-000000000001',false);
SELECT set_config('app.principal_id','d1110000-0000-0000-0000-000000000001',false);
SELECT set_config('app.sql011_auth_delegation',grant_caller_delegation('d1120000-0000-0000-0000-000000000001')::text,false);
SELECT set_config('app.sql011_service_delegation',grant_caller_delegation('d1120000-0000-0000-0000-000000000002')::text,false);
SELECT set_config('app.sql011_anonymous_delegation',grant_caller_delegation('d1120000-0000-0000-0000-000000000003')::text,false);

-- QSA-003 risk demonstration: app.principal_id is a caller-writable setting.
-- Switching it to another active Principal lets this same runtime session act as that Principal.
SELECT set_config('app.principal_id','d1110000-0000-0000-0000-000000000002',false);
SELECT grant_caller_delegation('d1120000-0000-0000-0000-000000000001');
SELECT tt.chk('QSA-003 runtime can forge Principal GUC and grant as that Principal',
 $q$SELECT count(*)=1 FROM principal_caller_delegations
     WHERE tenant_id='d1100000-0000-0000-0000-000000000001'
       AND principal_id='d1110000-0000-0000-0000-000000000002'
       AND caller_id='d1120000-0000-0000-0000-000000000001'
       AND revoked_at IS NULL$q$);
SELECT set_config('app.principal_id','d1110000-0000-0000-0000-000000000001',false);

SELECT tt.chk('SQL-011 principal can delegate to Authenticated, Service and Anonymous callers',
 $q$SELECT count(*)=3 FROM principal_caller_delegations
     WHERE tenant_id='d1100000-0000-0000-0000-000000000001'
       AND principal_id='d1110000-0000-0000-0000-000000000001'
       AND revoked_at IS NULL$q$);
SELECT tt.chk('SQL-011 caller kind remains independently represented',
 $q$SELECT count(DISTINCT c.caller_kind)=3
       FROM principal_caller_delegations d JOIN callers c
         ON c.tenant_id=d.tenant_id AND c.id=d.caller_id
      WHERE d.principal_id='d1110000-0000-0000-0000-000000000001'
        AND d.revoked_at IS NULL$q$);
SELECT tt.chk('SQL-011 resolver returns the explicitly delegated Caller',
 $q$SELECT EXISTS (SELECT 1 FROM resolve_delegated_caller('d1120000-0000-0000-0000-000000000001')
                    WHERE caller_id='d1120000-0000-0000-0000-000000000001'
                      AND caller_kind='Authenticated')$q$);
SELECT tt.chk('SQL-011 resolver supports Service Caller',
 $q$SELECT EXISTS (SELECT 1 FROM resolve_delegated_caller('d1120000-0000-0000-0000-000000000002')
                    WHERE caller_kind='Service')$q$);
SELECT tt.chk('SQL-011 resolver supports Anonymous Caller',
 $q$SELECT EXISTS (SELECT 1 FROM resolve_delegated_caller('d1120000-0000-0000-0000-000000000003')
                    WHERE caller_kind='Anonymous')$q$);
SELECT tt.try('SQL-011 resolver rejects an undelegated Caller','err',
 $q$SELECT * FROM resolve_delegated_caller('d1120000-0000-0000-0000-000000000004')$q$);
-- Establish a row in tenant B, then prove tenant A cannot read it.
SELECT set_config('app.tenant_id','d1100000-0000-0000-0000-000000000002',false);
SELECT set_config('app.principal_id','d1110000-0000-0000-0000-000000000003',false);
SELECT grant_caller_delegation('d1120000-0000-0000-0000-000000000004');
SELECT set_config('app.tenant_id','d1100000-0000-0000-0000-000000000001',false);
SELECT set_config('app.principal_id','d1110000-0000-0000-0000-000000000001',false);
SELECT tt.try('SQL-011 duplicate active delegation rejected','err',
 $q$SELECT grant_caller_delegation('d1120000-0000-0000-0000-000000000001')$q$);
SELECT tt.try('SQL-011 cross-tenant Caller cannot be delegated','err',
 $q$SELECT grant_caller_delegation('d1120000-0000-0000-0000-000000000004')$q$);


SELECT tt.chk('SQL-011 delegation table has ENABLE and FORCE RLS',
 $q$SELECT c.relrowsecurity AND c.relforcerowsecurity
       FROM pg_class c WHERE c.oid='public.principal_caller_delegations'::regclass$q$);
SELECT tt.chk('SQL-011 runtime cannot see another tenant delegation scope',
 $q$SELECT count(*)=0 FROM principal_caller_delegations
      WHERE tenant_id='d1100000-0000-0000-0000-000000000002'$q$);

-- A different authenticated Principal cannot revoke another Principal's grant.
SELECT set_config('app.principal_id','d1110000-0000-0000-0000-000000000002',false);
SELECT tt.chk('SQL-011 another principal cannot revoke this delegation',
 $q$SELECT NOT revoke_caller_delegation(current_setting('app.sql011_auth_delegation')::uuid)$q$);
SELECT set_config('app.principal_id','d1110000-0000-0000-0000-000000000001',false);
SELECT tt.chk('SQL-011 grantor can revoke own delegation',
 $q$SELECT revoke_caller_delegation(current_setting('app.sql011_auth_delegation')::uuid)$q$);
SELECT tt.chk('SQL-011 revocation records actor and is effective',
 $q$SELECT revoked_at IS NOT NULL
          AND revoked_by_principal_id='d1110000-0000-0000-0000-000000000001'
       FROM principal_caller_delegations
      WHERE delegation_id=current_setting('app.sql011_auth_delegation')::uuid$q$);
SELECT tt.try('SQL-011 resolver rejects a revoked delegation','err',
 $q$SELECT * FROM resolve_delegated_caller('d1120000-0000-0000-0000-000000000001')$q$);
SELECT set_config('app.sql011_regrant',grant_caller_delegation('d1120000-0000-0000-0000-000000000001')::text,false);
SELECT tt.chk('SQL-011 re-grant creates a new active historical record',
 $q$SELECT count(*)=2 AND count(*) FILTER (WHERE revoked_at IS NULL)=1
       FROM principal_caller_delegations
      WHERE tenant_id='d1100000-0000-0000-0000-000000000001'
        AND principal_id='d1110000-0000-0000-0000-000000000001'
        AND caller_id='d1120000-0000-0000-0000-000000000001'$q$);

SELECT tt.try('SQL-011 runtime cannot insert delegation rows directly','err',
 $q$INSERT INTO principal_caller_delegations(delegation_id,tenant_id,principal_id,caller_id)
     VALUES (gen_random_uuid(),'d1100000-0000-0000-0000-000000000001',
             'd1110000-0000-0000-0000-000000000001','d1120000-0000-0000-0000-000000000001')$q$);
SELECT tt.try('SQL-011 runtime cannot update delegation rows directly','err',
 $q$UPDATE principal_caller_delegations SET revoked_at=now()$q$);
RESET ROLE;

-- Missing trusted principal context must fail closed.
SET ROLE qembed_runtime;
SELECT set_config('app.tenant_id','d1100000-0000-0000-0000-000000000001',false);
SELECT set_config('app.principal_id','',false);
SELECT tt.try('SQL-011 delegation requires authenticated principal context','err',
 $q$SELECT grant_caller_delegation('d1120000-0000-0000-0000-000000000001')$q$);
RESET ROLE;


-- Delegation history cannot be rewritten or physically deleted.
SELECT tt.try('SQL-011 revoked delegation cannot be reactivated','err',
 $q$UPDATE principal_caller_delegations SET revoked_at=NULL, revoked_by_principal_id=NULL
      WHERE delegation_id=current_setting('app.sql011_auth_delegation')::uuid$q$);
SELECT tt.try('SQL-011 delegation history cannot be deleted','err',
 $q$DELETE FROM principal_caller_delegations
      WHERE delegation_id=current_setting('app.sql011_auth_delegation')::uuid$q$);

-- Revoking a Caller makes it ineligible for future grants, even if a prior grant exists.
UPDATE callers SET revoked_at=now()
 WHERE tenant_id='d1100000-0000-0000-0000-000000000001'
   AND id='d1120000-0000-0000-0000-000000000002';
SET ROLE qembed_runtime;
SELECT set_config('app.tenant_id','d1100000-0000-0000-0000-000000000001',false);
SELECT set_config('app.principal_id','d1110000-0000-0000-0000-000000000001',false);
SELECT tt.try('SQL-011 revoked Caller cannot receive a new delegation','err',
 $q$SELECT grant_caller_delegation('d1120000-0000-0000-0000-000000000002')$q$);
SELECT tt.try('SQL-011 resolver rejects a revoked Caller','err',
 $q$SELECT * FROM resolve_delegated_caller('d1120000-0000-0000-0000-000000000002')$q$);
SELECT tt.try('QSA-005 runtime cannot reactivate a revoked Caller','err',
 $q$UPDATE callers SET revoked_at=NULL
      WHERE tenant_id='d1100000-0000-0000-0000-000000000001'
        AND id='d1120000-0000-0000-0000-000000000002'$q$);
SELECT tt.try('QSA-005 runtime cannot rewrite Caller revocation timestamp','err',
 $q$UPDATE callers SET revoked_at=clock_timestamp()
      WHERE tenant_id='d1100000-0000-0000-0000-000000000001'
        AND id='d1120000-0000-0000-0000-000000000002'$q$);
SELECT tt.try('QSA-005 Caller token identity cannot be rewritten','err',
 $q$UPDATE callers SET token_hash=digest('replacement','sha256')
      WHERE tenant_id='d1100000-0000-0000-0000-000000000001'
        AND id='d1120000-0000-0000-0000-000000000002'$q$);
SELECT tt.chk('QSA-005 revoked Caller remains revoked after rejected rewrites',
 $q$SELECT revoked_at IS NOT NULL FROM callers
      WHERE tenant_id='d1100000-0000-0000-0000-000000000001'
        AND id='d1120000-0000-0000-0000-000000000002'$q$);
RESET ROLE;

-- Disabled principals cannot create new delegations.
UPDATE owner_principals SET disabled_at=now()
 WHERE tenant_id='d1100000-0000-0000-0000-000000000001'
   AND caller_id='d1110000-0000-0000-0000-000000000001';
SET ROLE qembed_runtime;
SELECT set_config('app.tenant_id','d1100000-0000-0000-0000-000000000001',false);
SELECT set_config('app.principal_id','d1110000-0000-0000-0000-000000000001',false);
SELECT tt.try('SQL-011 disabled principal cannot create delegation','err',
 $q$SELECT grant_caller_delegation('d1120000-0000-0000-0000-000000000002')$q$);
SELECT tt.try('SQL-011 disabled principal cannot resolve a delegated Caller','err',
 $q$SELECT * FROM resolve_delegated_caller('d1120000-0000-0000-0000-000000000001')$q$);
RESET ROLE;
