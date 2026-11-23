-- RUST-058c / RT-058: align Principal -> Caller delegation with the canonical
-- Principal identity model and make Anonymous invocation an Object-level policy.
-- Apply after the RT-050 verified-context migration.
BEGIN;

DO $preflight$
BEGIN
    IF to_regclass('public.principals') IS NULL
       OR to_regclass('public.owner_principals') IS NULL
       OR to_regclass('public.principal_caller_delegations') IS NULL
       OR to_regclass('public.objects') IS NULL
       OR to_regprocedure('qembed_crypto.current_tenant_id()') IS NULL
       OR to_regprocedure('qembed_crypto.current_principal_id()') IS NULL
       OR NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'qembed_definer') THEN
        RAISE EXCEPTION 'RT-058 requires canonical Principal tables and RT-050 verified context';
    END IF;
END
$preflight$;

-- Preserve the existing Owner API identity while moving delegation FKs to
-- principals. Legacy Owner credentials remain the authentication source for
-- that API; the synthetic digest is deliberately not a usable credential.
INSERT INTO principals (id, tenant_id, kind, key_hash, revoked_at)
SELECT op.caller_id,
       op.tenant_id,
       'TenantOwner',
       digest('legacy-owner-principal:' || op.tenant_id::text || ':' || op.caller_id::text, 'sha256'),
       op.disabled_at
  FROM owner_principals AS op
ON CONFLICT (id) DO NOTHING;

CREATE OR REPLACE FUNCTION sync_legacy_owner_principal()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $sync_legacy_owner_principal$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO principals (id, tenant_id, kind, key_hash, revoked_at)
        VALUES (
            NEW.caller_id, NEW.tenant_id, 'TenantOwner',
            digest('legacy-owner-principal:' || NEW.tenant_id::text || ':' || NEW.caller_id::text, 'sha256'),
            NEW.disabled_at
        )
        ON CONFLICT (id) DO NOTHING;
        RETURN NEW;
    END IF;
    IF NEW.disabled_at IS DISTINCT FROM OLD.disabled_at THEN
        UPDATE principals SET revoked_at = NEW.disabled_at
         WHERE id = NEW.caller_id AND tenant_id = NEW.tenant_id
           AND kind = 'TenantOwner'
           AND (revoked_at IS NULL OR NEW.disabled_at IS NOT NULL);
    END IF;
    RETURN NEW;
END
$sync_legacy_owner_principal$;

DROP TRIGGER IF EXISTS trg_sync_legacy_owner_principal ON owner_principals;
CREATE TRIGGER trg_sync_legacy_owner_principal
    AFTER INSERT OR UPDATE OF disabled_at ON owner_principals
    FOR EACH ROW EXECUTE FUNCTION sync_legacy_owner_principal();

ALTER FUNCTION sync_legacy_owner_principal() OWNER TO qembed_definer;
DROP POLICY IF EXISTS definer_owner_sync ON principals;
CREATE POLICY definer_owner_sync ON principals FOR ALL TO qembed_definer USING (true) WITH CHECK (true);
GRANT INSERT, UPDATE ON principals TO qembed_definer;

DO $identity_check$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM owner_principals op
          LEFT JOIN principals p
            ON p.id = op.caller_id AND p.tenant_id = op.tenant_id
         WHERE p.id IS NULL OR p.kind <> 'TenantOwner'
    ) THEN
        RAISE EXCEPTION 'legacy Owner identity cannot be mapped to a matching TenantOwner Principal';
    END IF;
END
$identity_check$;

ALTER TABLE objects
    ADD COLUMN IF NOT EXISTS anonymous_invocation_enabled BOOLEAN NOT NULL DEFAULT TRUE;

-- Delegations now target any active Principal in the same tenant. The actor
-- that granted/revoked a delegation is recorded separately from its recipient.
ALTER TABLE principal_caller_delegations
    DROP CONSTRAINT IF EXISTS principal_caller_delegations_check1,
    DROP CONSTRAINT IF EXISTS principal_caller_delegations_principal_fk,
    DROP CONSTRAINT IF EXISTS principal_caller_delegations_revoker_fk,
    DROP CONSTRAINT IF EXISTS principal_caller_delegations_tenant_id_principal_id_fkey,
    DROP CONSTRAINT IF EXISTS principal_caller_delegations_tenant_id_revoked_by_principal_id_fkey;

ALTER TABLE principal_caller_delegations
    ADD CONSTRAINT principal_caller_delegations_principal_fk
        FOREIGN KEY (tenant_id, principal_id)
        REFERENCES principals (tenant_id, id) ON DELETE RESTRICT,
    ADD CONSTRAINT principal_caller_delegations_revoker_fk
        FOREIGN KEY (tenant_id, revoked_by_principal_id)
        REFERENCES principals (tenant_id, id) ON DELETE RESTRICT;

-- Remove the old self-delegation-only grant function. The two-argument form
-- lets a TenantOwner grant a Caller to another Principal in the same tenant.
DROP FUNCTION IF EXISTS grant_caller_delegation(UUID);

CREATE FUNCTION grant_caller_delegation(
    p_target_principal_id UUID,
    p_caller_id UUID
)
RETURNS UUID
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $grant_caller_delegation$
DECLARE
    v_tenant_id UUID := qembed_crypto.current_tenant_id();
    v_actor_principal_id UUID := qembed_crypto.current_principal_id();
    v_delegation_id UUID := gen_random_uuid();
BEGIN
    IF v_tenant_id IS NULL OR v_actor_principal_id IS NULL
       OR p_target_principal_id IS NULL OR p_caller_id IS NULL THEN
        RAISE EXCEPTION 'tenant, authenticated Owner, target Principal and Caller are required'
            USING ERRCODE = '42501';
    END IF;

    PERFORM 1
      FROM principals actor
     WHERE actor.tenant_id = v_tenant_id
       AND actor.id = v_actor_principal_id
       AND actor.kind = 'TenantOwner'
       AND actor.revoked_at IS NULL
     FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'only an active TenantOwner may grant Caller delegation'
            USING ERRCODE = '42501';
    END IF;

    -- Legacy Owner disablement remains authoritative until the Owner credential
    -- store is retired. Other Principal kinds use principals.revoked_at.
    PERFORM 1
      FROM principals target
     WHERE target.tenant_id = v_tenant_id
       AND target.id = p_target_principal_id
       AND target.revoked_at IS NULL
       AND (
           target.kind <> 'TenantOwner'
           OR EXISTS (
               SELECT 1 FROM owner_principals legacy
                WHERE legacy.tenant_id = target.tenant_id
                  AND legacy.caller_id = target.id
                  AND legacy.disabled_at IS NULL
           )
       )
     FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'target Principal is not active in this tenant'
            USING ERRCODE = '42501';
    END IF;

    PERFORM 1
      FROM callers caller
     WHERE caller.tenant_id = v_tenant_id
       AND caller.id = p_caller_id
       AND caller.revoked_at IS NULL
     FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'target Caller is not active in this tenant'
            USING ERRCODE = '42501';
    END IF;

    INSERT INTO principal_caller_delegations
        (delegation_id, tenant_id, principal_id, caller_id)
    VALUES
        (v_delegation_id, v_tenant_id, p_target_principal_id, p_caller_id);

    RETURN v_delegation_id;
END
$grant_caller_delegation$;

-- Compatibility overload: preserve Owner self-delegation callers while
-- making the target Principal explicit in all new code.
CREATE FUNCTION grant_caller_delegation(p_caller_id UUID)
RETURNS UUID
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $grant_caller_delegation_legacy$
DECLARE
    v_principal_id UUID := qembed_crypto.current_principal_id();
BEGIN
    IF v_principal_id IS NULL THEN
        RAISE EXCEPTION 'authenticated Owner context is required'
            USING ERRCODE = '42501';
    END IF;
    RETURN grant_caller_delegation(v_principal_id, p_caller_id);
END
$grant_caller_delegation_legacy$;

CREATE OR REPLACE FUNCTION revoke_caller_delegation(p_delegation_id UUID)
RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $revoke_caller_delegation$
DECLARE
    v_tenant_id UUID := qembed_crypto.current_tenant_id();
    v_actor_principal_id UUID := qembed_crypto.current_principal_id();
BEGIN
    IF v_tenant_id IS NULL OR v_actor_principal_id IS NULL OR p_delegation_id IS NULL THEN
        RAISE EXCEPTION 'tenant, authenticated Owner and delegation are required'
            USING ERRCODE = '42501';
    END IF;

    PERFORM 1
      FROM principals actor
     WHERE actor.tenant_id = v_tenant_id
       AND actor.id = v_actor_principal_id
       AND actor.kind = 'TenantOwner'
       AND actor.revoked_at IS NULL
       AND (
           actor.kind <> 'TenantOwner'
           OR EXISTS (
               SELECT 1 FROM owner_principals legacy
                WHERE legacy.tenant_id = actor.tenant_id
                  AND legacy.caller_id = actor.id
                  AND legacy.disabled_at IS NULL
           )
       )
     FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'only an active TenantOwner may revoke Caller delegation'
            USING ERRCODE = '42501';
    END IF;

    UPDATE principal_caller_delegations
       SET revoked_at = clock_timestamp(),
           revoked_by_principal_id = v_actor_principal_id
     WHERE delegation_id = p_delegation_id
       AND tenant_id = v_tenant_id
       AND revoked_at IS NULL;
    RETURN FOUND;
END
$revoke_caller_delegation$;

-- Runtime's signed-context resolver receives explicit claims from the trusted
-- ContextIssuer. It locks the target Principal, Caller and delegation together.
CREATE OR REPLACE FUNCTION resolve_delegated_caller(
    p_tenant_id UUID,
    p_principal_id UUID,
    p_caller_id UUID
)
RETURNS TABLE (delegation_id UUID, caller_id UUID, caller_kind TEXT)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $resolve_delegated_caller$
BEGIN
    IF p_tenant_id IS NULL OR p_principal_id IS NULL OR p_caller_id IS NULL THEN
        RAISE EXCEPTION 'explicit tenant, authenticated Principal and Caller are required'
            USING ERRCODE = '42501';
    END IF;

    RETURN QUERY
    SELECT d.delegation_id, c.id, c.caller_kind
      FROM principal_caller_delegations d
      JOIN principals p
        ON p.tenant_id = d.tenant_id AND p.id = d.principal_id
      JOIN callers c
        ON c.tenant_id = d.tenant_id AND c.id = d.caller_id
     WHERE d.tenant_id = p_tenant_id
       AND d.principal_id = p_principal_id
       AND d.caller_id = p_caller_id
       AND d.revoked_at IS NULL
       AND p.revoked_at IS NULL
       AND (
           p.kind <> 'TenantOwner'
           OR EXISTS (
               SELECT 1 FROM owner_principals legacy
                WHERE legacy.tenant_id = p.tenant_id
                  AND legacy.caller_id = p.id
                  AND legacy.disabled_at IS NULL
           )
       )
       AND c.revoked_at IS NULL
     FOR SHARE OF d, p, c;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'no active delegation for this Principal and Caller'
            USING ERRCODE = '42501';
    END IF;
END
$resolve_delegated_caller$;

ALTER FUNCTION grant_caller_delegation(UUID, UUID) OWNER TO qembed_definer;
ALTER FUNCTION grant_caller_delegation(UUID) OWNER TO qembed_definer;
ALTER FUNCTION revoke_caller_delegation(UUID) OWNER TO qembed_definer;
ALTER FUNCTION resolve_delegated_caller(UUID, UUID, UUID) OWNER TO qembed_definer;

REVOKE ALL ON FUNCTION grant_caller_delegation(UUID, UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION grant_caller_delegation(UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION revoke_caller_delegation(UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION resolve_delegated_caller(UUID, UUID, UUID) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION grant_caller_delegation(UUID, UUID) TO qembed_runtime;
GRANT EXECUTE ON FUNCTION grant_caller_delegation(UUID) TO qembed_runtime;
GRANT EXECUTE ON FUNCTION revoke_caller_delegation(UUID) TO qembed_runtime;
GRANT EXECUTE ON FUNCTION resolve_delegated_caller(UUID, UUID, UUID) TO qembed_runtime;

GRANT SELECT ON principals TO qembed_definer;
GRANT SELECT, INSERT, UPDATE ON principal_caller_delegations TO qembed_definer;
GRANT UPDATE (revoked_at) ON callers TO qembed_definer;

COMMENT ON COLUMN objects.anonymous_invocation_enabled IS
    'When true, this Object may be invoked without an authenticated Principal; defaults to public.';

COMMIT;
