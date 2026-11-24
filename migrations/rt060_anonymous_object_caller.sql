-- RT-060: one server-owned Anonymous Caller per public Object.
BEGIN;

DO $preflight$
BEGIN
    IF to_regclass('public.objects') IS NULL
       OR to_regclass('public.callers') IS NULL
       OR to_regprocedure('qembed_crypto.current_subject_kind()') IS NULL
       OR to_regprocedure('qembed_crypto.current_object_id()') IS NULL
       OR to_regprocedure('qembed_crypto.current_anonymous_fingerprint()') IS NULL
       OR NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'qembed_runtime')
       OR NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'qembed_definer') THEN
        RAISE EXCEPTION 'RT-060 requires RT-058 Object/Caller schema and RT-059 qctx2 accessors';
    END IF;
END
$preflight$;

CREATE TABLE object_anonymous_callers (
    tenant_id UUID NOT NULL,
    object_id UUID NOT NULL,
    caller_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, object_id),
    UNIQUE (tenant_id, caller_id),
    FOREIGN KEY (tenant_id, object_id)
        REFERENCES objects (tenant_id, object_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, caller_id)
        REFERENCES callers (tenant_id, id) ON DELETE RESTRICT
);

ALTER TABLE object_anonymous_callers ENABLE ROW LEVEL SECURITY;
ALTER TABLE object_anonymous_callers FORCE ROW LEVEL SECURITY;

CREATE POLICY object_anonymous_callers_definer_scope
    ON object_anonymous_callers
    FOR ALL TO qembed_definer
    USING (tenant_id = qembed_crypto.current_tenant_id())
    WITH CHECK (tenant_id = qembed_crypto.current_tenant_id());

REVOKE ALL ON object_anonymous_callers FROM PUBLIC, qembed_runtime;
GRANT SELECT, INSERT ON object_anonymous_callers TO qembed_definer;
-- SECURITY DEFINER routines lock Object and Caller lifecycle rows before returning
-- the Anonymous Caller; the runtime role receives no direct table access.
GRANT SELECT ON objects, callers TO qembed_definer;
-- SELECT ... FOR SHARE requires UPDATE privilege; object_id is immutable under
-- the canonical trigger, so this grants row-lock capability without mutation.
GRANT UPDATE (object_id) ON objects TO qembed_definer;
GRANT INSERT ON callers TO qembed_definer;

CREATE FUNCTION qembed_crypto.get_or_create_anonymous_caller(
    p_tenant_id UUID,
    p_object_id UUID
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, qembed_crypto, pg_temp
AS $get_or_create_anonymous_caller$
DECLARE
    v_fingerprint BYTEA := qembed_crypto.current_anonymous_fingerprint();
    v_token_hash BYTEA;
    v_caller_id UUID;
    v_mapped_caller_id UUID;
BEGIN
    IF p_tenant_id IS NULL OR p_object_id IS NULL
       OR qembed_crypto.current_tenant_id() IS DISTINCT FROM p_tenant_id
       OR qembed_crypto.current_subject_kind() IS DISTINCT FROM 'anonymous'
       OR qembed_crypto.current_principal_id() IS NOT NULL
       OR qembed_crypto.current_caller_id() IS NOT NULL
       OR qembed_crypto.current_object_id() IS DISTINCT FROM p_object_id
       OR v_fingerprint IS NULL OR octet_length(v_fingerprint) <> 32 THEN
        RAISE EXCEPTION 'valid qctx2 Anonymous bootstrap context is required'
            USING ERRCODE = '42501';
    END IF;

    PERFORM 1
      FROM objects
     WHERE tenant_id = p_tenant_id
       AND object_id = p_object_id
       AND anonymous_invocation_enabled IS TRUE
       AND state = 'active'
       AND published_version_id IS NOT NULL
     FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Object is not enabled for public invocation'
            USING ERRCODE = '42501';
    END IF;

    -- This digest is an Object-scoped synthetic token hash, not a network
    -- identifier. The per-request fingerprint remains only in the signed
    -- transaction context and Valkey rate-limit key.
    v_token_hash := digest(
        convert_to(
            'qembed:anonymous-object-caller:' || p_tenant_id::text || ':' || p_object_id::text,
            'UTF8'
        ),
        'sha256'
    );

    INSERT INTO callers (id, tenant_id, token_hash, caller_kind)
    VALUES (gen_random_uuid(), p_tenant_id, v_token_hash, 'Anonymous')
    ON CONFLICT (tenant_id, token_hash) DO NOTHING;

    SELECT id INTO v_caller_id
      FROM callers
     WHERE tenant_id = p_tenant_id
       AND token_hash = v_token_hash
       AND caller_kind = 'Anonymous'
       AND revoked_at IS NULL
     FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Object Anonymous Caller is inactive'
            USING ERRCODE = '42501';
    END IF;

    INSERT INTO object_anonymous_callers (tenant_id, object_id, caller_id)
    VALUES (p_tenant_id, p_object_id, v_caller_id)
    ON CONFLICT (tenant_id, object_id) DO NOTHING;

    SELECT caller_id INTO v_mapped_caller_id
      FROM object_anonymous_callers
     WHERE tenant_id = p_tenant_id
       AND object_id = p_object_id
     FOR SHARE;
    IF v_mapped_caller_id IS DISTINCT FROM v_caller_id THEN
        RAISE EXCEPTION 'Object Anonymous Caller mapping is inconsistent'
            USING ERRCODE = '23505';
    END IF;

    RETURN v_caller_id;
END
$get_or_create_anonymous_caller$;

CREATE FUNCTION qembed_crypto.resolve_anonymous_caller(
    p_tenant_id UUID,
    p_object_id UUID,
    p_caller_id UUID
)
RETURNS TABLE (caller_id UUID, caller_kind TEXT)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, qembed_crypto, pg_temp
AS $resolve_anonymous_caller$
DECLARE
    v_fingerprint BYTEA := qembed_crypto.current_anonymous_fingerprint();
    v_mapped_caller_id UUID;
    v_kind TEXT;
BEGIN
    IF p_tenant_id IS NULL OR p_object_id IS NULL OR p_caller_id IS NULL
       OR qembed_crypto.current_tenant_id() IS DISTINCT FROM p_tenant_id
       OR qembed_crypto.current_subject_kind() IS DISTINCT FROM 'anonymous'
       OR qembed_crypto.current_principal_id() IS NOT NULL
       OR qembed_crypto.current_caller_id() IS DISTINCT FROM p_caller_id
       OR qembed_crypto.current_object_id() IS DISTINCT FROM p_object_id
       OR v_fingerprint IS NULL OR octet_length(v_fingerprint) <> 32 THEN
        RAISE EXCEPTION 'valid qctx2 Anonymous invocation context is required'
            USING ERRCODE = '42501';
    END IF;

    PERFORM 1
      FROM objects
     WHERE tenant_id = p_tenant_id
       AND object_id = p_object_id
       AND anonymous_invocation_enabled IS TRUE
       AND state = 'active'
       AND published_version_id IS NOT NULL
     FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Object is not enabled for public invocation'
            USING ERRCODE = '42501';
    END IF;

    SELECT mapping.caller_id INTO v_mapped_caller_id
      FROM object_anonymous_callers AS mapping
     WHERE mapping.tenant_id = p_tenant_id
       AND mapping.object_id = p_object_id
     FOR SHARE;
    IF NOT FOUND OR v_mapped_caller_id IS DISTINCT FROM p_caller_id THEN
        RAISE EXCEPTION 'Anonymous Caller is not registered for this Object'
            USING ERRCODE = '42501';
    END IF;

    SELECT caller.caller_kind INTO v_kind
      FROM callers AS caller
     WHERE caller.tenant_id = p_tenant_id
       AND caller.id = p_caller_id
       AND caller.caller_kind = 'Anonymous'
       AND caller.revoked_at IS NULL
     FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Object Anonymous Caller is inactive'
            USING ERRCODE = '42501';
    END IF;

    RETURN QUERY SELECT p_caller_id, v_kind;
END
$resolve_anonymous_caller$;

ALTER FUNCTION qembed_crypto.get_or_create_anonymous_caller(UUID, UUID) OWNER TO qembed_definer;
ALTER FUNCTION qembed_crypto.resolve_anonymous_caller(UUID, UUID, UUID) OWNER TO qembed_definer;

REVOKE ALL ON FUNCTION qembed_crypto.get_or_create_anonymous_caller(UUID, UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION qembed_crypto.resolve_anonymous_caller(UUID, UUID, UUID) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION qembed_crypto.get_or_create_anonymous_caller(UUID, UUID) TO qembed_runtime, qembed_definer;
GRANT EXECUTE ON FUNCTION qembed_crypto.resolve_anonymous_caller(UUID, UUID, UUID) TO qembed_runtime, qembed_definer;

COMMIT;
