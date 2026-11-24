-- RUST-061: Runtime-side Caller erasure and privileged restore replay.
--
-- Apply to the Runtime database after the canonical clean-install schema and
-- RT-050 signed-context migration. The Control-plane tombstone table is created
-- separately by rt061_control_plane_caller_deletion_ledger.sql.

BEGIN;

DO $roles$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'qembed_restore') THEN
        CREATE ROLE qembed_restore
            NOLOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
    END IF;
END
$roles$;

ALTER ROLE qembed_restore
    NOLOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;

GRANT USAGE ON SCHEMA qembed_crypto TO qembed_runtime, qembed_restore, qembed_definer;

-- qembed_definer is already allowed to read Caller and ToolExecution state and
-- erase messages, episodic memories, idempotency rows and encrypted tool payloads.
-- These additional privileges are the minimum required for the erasure routine.
GRANT UPDATE (cancel_requested_at) ON object_invocations TO qembed_definer;
GRANT SELECT ON policy_decisions TO qembed_definer;

CREATE POLICY definer_access ON policy_decisions
    FOR ALL TO qembed_definer
    USING (true)
    WITH CHECK (true);

CREATE OR REPLACE FUNCTION qembed_crypto.erase_caller_data_internal(
    p_tenant_id UUID,
    p_caller_id UUID
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, qembed_crypto, pg_temp
AS $erase_caller_data_internal$
BEGIN
    UPDATE callers
       SET revoked_at = COALESCE(revoked_at, clock_timestamp())
     WHERE tenant_id = p_tenant_id
       AND id = p_caller_id;

    -- A missing Caller cannot own rows because every derived table has a
    -- tenant-consistent FK to callers.
    IF NOT FOUND THEN
        RETURN TRUE;
    END IF;

    -- Revocation blocks new work. Propagate cancellation to work already in
    -- flight, then defer physical erasure until workers reach terminal states.
    UPDATE object_invocations
       SET cancel_requested_at = COALESCE(cancel_requested_at, clock_timestamp())
     WHERE tenant_id = p_tenant_id
       AND caller_id = p_caller_id
       AND status NOT IN ('Completed', 'CompletedDegraded', 'Failed', 'Cancelled')
       AND cancel_requested_at IS NULL;

    IF EXISTS (
        SELECT 1
          FROM object_invocations
         WHERE tenant_id = p_tenant_id
           AND caller_id = p_caller_id
           AND status NOT IN ('Completed', 'CompletedDegraded', 'Failed', 'Cancelled')
    ) OR EXISTS (
        SELECT 1
          FROM tool_executions
         WHERE tenant_id = p_tenant_id
           AND caller_id = p_caller_id
           AND status NOT IN ('Succeeded', 'Failed')
    ) THEN
        RETURN FALSE;
    END IF;

    -- Tool payloads may contain encrypted arguments. Delete them through the
    -- immutable Allow decision that binds the command to this Caller.
    DELETE FROM tool_command_payloads payload
     USING policy_decisions decision
     WHERE payload.tenant_id = decision.tenant_id
       AND payload.command_id = decision.command_id
       AND decision.tenant_id = p_tenant_id
       AND decision.caller_id = p_caller_id;

    DELETE FROM interaction_messages
     WHERE tenant_id = p_tenant_id
       AND caller_id = p_caller_id;

    DELETE FROM invocation_idempotency
     WHERE tenant_id = p_tenant_id
       AND caller_id = p_caller_id;

    DELETE FROM memories
     WHERE tenant_id = p_tenant_id
       AND caller_id = p_caller_id
       AND memory_kind = 'episodic';

    -- Keep execution/audit identity, but erase terminal tool output bytes.
    -- tool_execution_state_guard explicitly permits this qembed_definer-only
    -- retention-style transition for terminal rows.
    UPDATE tool_executions
       SET output = NULL,
           output_expires_at = NULL
     WHERE tenant_id = p_tenant_id
       AND caller_id = p_caller_id
       AND status IN ('Succeeded', 'Failed')
       AND output IS NOT NULL;

    RETURN TRUE;
END
$erase_caller_data_internal$;

CREATE OR REPLACE FUNCTION qembed_crypto.request_caller_deletion(
    p_tenant_id UUID,
    p_caller_id UUID
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, qembed_crypto, pg_temp
AS $request_caller_deletion$
BEGIN
    IF qembed_crypto.current_tenant_id() IS DISTINCT FROM p_tenant_id THEN
        RAISE EXCEPTION 'Caller deletion tenant context mismatch'
            USING ERRCODE = '42501';
    END IF;

    UPDATE callers
       SET revoked_at = COALESCE(revoked_at, clock_timestamp())
     WHERE tenant_id = p_tenant_id
       AND id = p_caller_id;

    IF NOT FOUND THEN
        RETURN FALSE;
    END IF;

    UPDATE object_invocations
       SET cancel_requested_at = COALESCE(cancel_requested_at, clock_timestamp())
     WHERE tenant_id = p_tenant_id
       AND caller_id = p_caller_id
       AND status NOT IN ('Completed', 'CompletedDegraded', 'Failed', 'Cancelled')
       AND cancel_requested_at IS NULL;

    RETURN TRUE;
END
$request_caller_deletion$;

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

    RETURN qembed_crypto.erase_caller_data_internal(p_tenant_id, p_caller_id);
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
    IF octet_length(p_caller_hash) <> 32
       OR octet_length(p_hmac_key) <> 32
       OR p_key_version <> 'v1' THEN
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
        RETURN TRUE;
    END IF;

    RETURN qembed_crypto.erase_caller_data_internal(p_tenant_id, v_caller_id);
END
$replay_caller_deletion$;

ALTER FUNCTION qembed_crypto.erase_caller_data_internal(UUID, UUID) OWNER TO qembed_definer;
ALTER FUNCTION qembed_crypto.request_caller_deletion(UUID, UUID) OWNER TO qembed_definer;
ALTER FUNCTION qembed_crypto.erase_caller_data(UUID, UUID) OWNER TO qembed_definer;
ALTER FUNCTION qembed_crypto.replay_caller_deletion(UUID, BYTEA, TEXT, BYTEA) OWNER TO qembed_definer;

REVOKE ALL ON FUNCTION qembed_crypto.erase_caller_data_internal(UUID, UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION qembed_crypto.request_caller_deletion(UUID, UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION qembed_crypto.erase_caller_data(UUID, UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION qembed_crypto.replay_caller_deletion(UUID, BYTEA, TEXT, BYTEA) FROM PUBLIC;

REVOKE ALL ON FUNCTION qembed_crypto.erase_caller_data_internal(UUID, UUID)
    FROM qembed_runtime, qembed_restore, qembed_admin, qembed_dispatcher, qembed_retention, qembed_worker;
GRANT EXECUTE ON FUNCTION qembed_crypto.request_caller_deletion(UUID, UUID) TO qembed_runtime;
GRANT EXECUTE ON FUNCTION qembed_crypto.erase_caller_data(UUID, UUID) TO qembed_runtime;
GRANT EXECUTE ON FUNCTION qembed_crypto.replay_caller_deletion(UUID, BYTEA, TEXT, BYTEA)
    TO qembed_restore;

COMMIT;
