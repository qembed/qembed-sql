-- RUST-061b: do not report erasure complete until every targeted data class is absent.
BEGIN;

CREATE FUNCTION qembed_crypto.erase_caller_data_verified(
    p_tenant_id UUID,
    p_caller_id UUID
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, qembed_crypto, pg_temp
AS $erase_caller_data_verified$
BEGIN
    IF NOT qembed_crypto.erase_caller_data_internal(p_tenant_id, p_caller_id) THEN
        RETURN FALSE;
    END IF;

    IF EXISTS (
        SELECT 1 FROM callers
         WHERE tenant_id = p_tenant_id
           AND id = p_caller_id
           AND revoked_at IS NULL
    ) OR EXISTS (
        SELECT 1 FROM object_invocations
         WHERE tenant_id = p_tenant_id
           AND caller_id = p_caller_id
           AND status NOT IN ('Completed', 'CompletedDegraded', 'Failed', 'Cancelled')
    ) OR EXISTS (
        SELECT 1 FROM tool_executions
         WHERE tenant_id = p_tenant_id
           AND caller_id = p_caller_id
           AND status NOT IN ('Succeeded', 'Failed')
    ) OR EXISTS (
        SELECT 1 FROM interaction_messages
         WHERE tenant_id = p_tenant_id
           AND caller_id = p_caller_id
    ) OR EXISTS (
        SELECT 1 FROM invocation_idempotency
         WHERE tenant_id = p_tenant_id
           AND caller_id = p_caller_id
    ) OR EXISTS (
        SELECT 1 FROM memories
         WHERE tenant_id = p_tenant_id
           AND caller_id = p_caller_id
           AND memory_kind = 'episodic'
    ) OR EXISTS (
        SELECT 1
          FROM tool_command_payloads payload
          JOIN policy_decisions decision
            ON decision.tenant_id = payload.tenant_id
           AND decision.command_id = payload.command_id
         WHERE decision.tenant_id = p_tenant_id
           AND decision.caller_id = p_caller_id
    ) OR EXISTS (
        SELECT 1 FROM tool_executions
         WHERE tenant_id = p_tenant_id
           AND caller_id = p_caller_id
           AND (output IS NOT NULL OR output_expires_at IS NOT NULL)
    ) THEN
        RETURN FALSE;
    END IF;

    RETURN TRUE;
END
$erase_caller_data_verified$;

CREATE OR REPLACE FUNCTION qembed_crypto.erase_caller_data(
    p_tenant_id UUID,
    p_caller_id UUID
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, qembed_crypto, pg_temp
AS $erase_caller_data$
BEGIN
    IF qembed_crypto.current_tenant_id() IS DISTINCT FROM p_tenant_id THEN
        RAISE EXCEPTION 'Caller erasure tenant context mismatch'
            USING ERRCODE = '42501';
    END IF;

    RETURN qembed_crypto.erase_caller_data_verified(p_tenant_id, p_caller_id);
END
$erase_caller_data$;

CREATE OR REPLACE FUNCTION qembed_crypto.replay_caller_deletion(
    p_tenant_id UUID,
    p_caller_hash BYTEA,
    p_key_version TEXT,
    p_hmac_key BYTEA
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, qembed_crypto, pg_temp
AS $replay_caller_deletion$
DECLARE
    v_caller_id UUID;
BEGIN
    IF p_caller_hash IS NULL
       OR octet_length(p_caller_hash) <> 32
       OR p_hmac_key IS NULL
       OR octet_length(p_hmac_key) <> 32
       OR p_key_version IS DISTINCT FROM 'v1' THEN
        RAISE EXCEPTION 'Unsupported Caller deletion tombstone format'
            USING ERRCODE = '22023';
    END IF;

    SELECT caller.id
      INTO v_caller_id
      FROM callers caller
     WHERE caller.tenant_id = p_tenant_id
       AND public.hmac(
            convert_to('qembed/caller-deletion/v1', 'UTF8')
            || decode('00', 'hex')
            || pg_catalog.uuid_send(p_tenant_id)
            || pg_catalog.uuid_send(caller.id),
            p_hmac_key,
            'sha256'
       ) = p_caller_hash
     LIMIT 1;

    IF v_caller_id IS NULL THEN
        -- Caller rows cannot be physically removed while caller-derived rows
        -- remain because the canonical schema enforces tenant-consistent FKs.
        RETURN TRUE;
    END IF;

    RETURN qembed_crypto.erase_caller_data_verified(p_tenant_id, v_caller_id);
END
$replay_caller_deletion$;

ALTER FUNCTION qembed_crypto.erase_caller_data_verified(UUID, UUID) OWNER TO qembed_definer;
ALTER FUNCTION qembed_crypto.erase_caller_data(UUID, UUID) OWNER TO qembed_definer;
ALTER FUNCTION qembed_crypto.replay_caller_deletion(UUID, BYTEA, TEXT, BYTEA) OWNER TO qembed_definer;

REVOKE ALL ON FUNCTION qembed_crypto.erase_caller_data_verified(UUID, UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION qembed_crypto.erase_caller_data_verified(UUID, UUID)
    FROM qembed_runtime, qembed_restore, qembed_admin, qembed_dispatcher, qembed_retention, qembed_worker;
REVOKE ALL ON FUNCTION qembed_crypto.erase_caller_data(UUID, UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION qembed_crypto.replay_caller_deletion(UUID, BYTEA, TEXT, BYTEA) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION qembed_crypto.erase_caller_data(UUID, UUID) TO qembed_runtime;
GRANT EXECUTE ON FUNCTION qembed_crypto.replay_caller_deletion(UUID, BYTEA, TEXT, BYTEA)
    TO qembed_restore;

COMMIT;
