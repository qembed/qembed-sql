-- RT-050 / QSA-003: migrate SQL identity consumers to verified qctx1 claims.
-- Requires the verifier extension, key registry, verified_context(text), and
-- typed current_* accessors to be installed first.
BEGIN;
DO $preflight$
BEGIN
 IF to_regprocedure('qembed_crypto.verified_context(text)') IS NULL
 OR to_regprocedure('qembed_crypto.current_tenant_id()') IS NULL
 OR to_regprocedure('qembed_crypto.current_principal_id()') IS NULL
 OR to_regprocedure('qembed_crypto.current_caller_id()') IS NULL THEN
   RAISE EXCEPTION 'RT-050 verifier and typed context accessors must be installed first';
 END IF;
 IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='qembed_definer') THEN
   RAISE EXCEPTION 'qembed_definer role is required';
 END IF;
END $preflight$;

GRANT EXECUTE ON FUNCTION qembed_crypto.current_tenant_id() TO qembed_definer;
GRANT EXECUTE ON FUNCTION qembed_crypto.current_principal_id() TO qembed_definer;
GRANT EXECUTE ON FUNCTION qembed_crypto.current_caller_id() TO qembed_definer;

DO $tenant_policies$
DECLARE t text;
BEGIN
 FOREACH t IN ARRAY ARRAY[
 'objects',
 'object_versions',
 'callers',
 'snapshots',
 'object_invocations',
 'invocation_idempotency',
 'interaction_messages',
 'knowledge_revisions',
 'knowledge_revision_log',
 'knowledge_documents',
 'knowledge_chunks',
 'knowledge_chunk_embeddings',
 'object_tools',
 'policy_decisions',
 'tool_command_payloads',
 'tool_executions',
 'events',
 'outbox_messages',
 'object_budgets',
 'budget_reservations',
 'provider_call_attempts',
 'usage_counters',
 'caller_usage_counters',
 'budget_event_dedup',
 'object_goals',
 'object_tasks',
 'deletion_jobs',
 'deletion_ledger',
 'principal_caller_delegations',
 'event_stream_counters'
 ] LOOP
  EXECUTE format('ALTER POLICY tenant_isolation ON %I TO qembed_runtime USING (tenant_id = (SELECT qembed_crypto.current_tenant_id())) WITH CHECK (tenant_id = (SELECT qembed_crypto.current_tenant_id()))',t);
 END LOOP;
END $tenant_policies$;

ALTER POLICY tenant_isolation ON memories TO qembed_runtime
 USING (tenant_id = (SELECT qembed_crypto.current_tenant_id())
   AND (memory_kind='semantic' OR caller_id=(SELECT qembed_crypto.current_caller_id())))
 WITH CHECK (tenant_id = (SELECT qembed_crypto.current_tenant_id())
   AND (memory_kind='semantic' OR caller_id=(SELECT qembed_crypto.current_caller_id())));

ALTER POLICY tenant_isolation ON memory_embeddings TO qembed_runtime
 USING (tenant_id = (SELECT qembed_crypto.current_tenant_id())
   AND EXISTS (SELECT 1 FROM memories m WHERE m.tenant_id=memory_embeddings.tenant_id
     AND m.object_id=memory_embeddings.object_id AND m.id=memory_embeddings.memory_id))
 WITH CHECK (tenant_id = (SELECT qembed_crypto.current_tenant_id())
   AND EXISTS (SELECT 1 FROM memories m WHERE m.tenant_id=memory_embeddings.tenant_id
     AND m.object_id=memory_embeddings.object_id AND m.id=memory_embeddings.memory_id));

ALTER POLICY tenant_isolation ON memory_conflicts TO qembed_runtime
 USING (tenant_id = (SELECT qembed_crypto.current_tenant_id())
   AND EXISTS (SELECT 1 FROM memories m WHERE m.tenant_id=memory_conflicts.tenant_id
     AND m.object_id=memory_conflicts.object_id AND m.id=memory_conflicts.memory_id)
   AND EXISTS (SELECT 1 FROM memories m WHERE m.tenant_id=memory_conflicts.tenant_id
     AND m.object_id=memory_conflicts.object_id AND m.id=memory_conflicts.conflicting_memory_id))
 WITH CHECK (tenant_id = (SELECT qembed_crypto.current_tenant_id())
   AND EXISTS (SELECT 1 FROM memories m WHERE m.tenant_id=memory_conflicts.tenant_id
     AND m.object_id=memory_conflicts.object_id AND m.id=memory_conflicts.memory_id)
   AND EXISTS (SELECT 1 FROM memories m WHERE m.tenant_id=memory_conflicts.tenant_id
     AND m.object_id=memory_conflicts.object_id AND m.id=memory_conflicts.conflicting_memory_id));

ALTER POLICY own_tenant ON tenants TO qembed_runtime USING (id=(SELECT qembed_crypto.current_tenant_id()));
ALTER POLICY own_tenant ON principals TO qembed_runtime USING (tenant_id=(SELECT qembed_crypto.current_tenant_id()));
ALTER POLICY ks_read ON kill_switches TO qembed_runtime
 USING (tenant_id IS NULL OR tenant_id=(SELECT qembed_crypto.current_tenant_id()));
ALTER POLICY ks_write ON kill_switches TO qembed_runtime
 USING (tenant_id=(SELECT qembed_crypto.current_tenant_id()))
 WITH CHECK (tenant_id=(SELECT qembed_crypto.current_tenant_id()));
ALTER POLICY tenant_isolation ON outbox_publication_receipts TO qembed_runtime
 USING (tenant_id=(SELECT qembed_crypto.current_tenant_id()))
 WITH CHECK (tenant_id=(SELECT qembed_crypto.current_tenant_id()));

CREATE OR REPLACE FUNCTION grant_caller_delegation(p_caller_id UUID)
RETURNS UUID
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $grant_caller_delegation$
DECLARE
  v_tenant_id UUID := qembed_crypto.current_tenant_id();
  v_principal_id UUID := qembed_crypto.current_principal_id();
  v_delegation_id UUID := gen_random_uuid();
BEGIN
  IF v_tenant_id IS NULL OR v_principal_id IS NULL THEN
    RAISE EXCEPTION 'tenant and authenticated principal context are required'
      USING ERRCODE = '42501';
  END IF;
  PERFORM 1 FROM owner_principals p
   WHERE p.tenant_id = v_tenant_id AND p.caller_id = v_principal_id
     AND p.disabled_at IS NULL
   FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'authenticated principal is not active in this tenant'
      USING ERRCODE = '42501';
  END IF;
  PERFORM 1 FROM callers c
   WHERE c.tenant_id = v_tenant_id AND c.id = p_caller_id
     AND c.revoked_at IS NULL
   FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'target caller is not active in this tenant'
      USING ERRCODE = '42501';
  END IF;
  INSERT INTO principal_caller_delegations
    (delegation_id, tenant_id, principal_id, caller_id)
  VALUES (v_delegation_id, v_tenant_id, v_principal_id, p_caller_id);
  RETURN v_delegation_id;
END
$grant_caller_delegation$;

CREATE OR REPLACE FUNCTION revoke_caller_delegation(p_delegation_id UUID)
RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $revoke_caller_delegation$
DECLARE
  v_tenant_id UUID := qembed_crypto.current_tenant_id();
  v_principal_id UUID := qembed_crypto.current_principal_id();
BEGIN
  IF v_tenant_id IS NULL OR v_principal_id IS NULL THEN
    RAISE EXCEPTION 'tenant and authenticated principal context are required'
      USING ERRCODE = '42501';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM owner_principals p
     WHERE p.tenant_id = v_tenant_id AND p.caller_id = v_principal_id
       AND p.disabled_at IS NULL
  ) THEN
    RAISE EXCEPTION 'authenticated principal is not active in this tenant'
      USING ERRCODE = '42501';
  END IF;
  UPDATE principal_caller_delegations
     SET revoked_at = clock_timestamp(), revoked_by_principal_id = v_principal_id
   WHERE delegation_id = p_delegation_id AND tenant_id = v_tenant_id
     AND principal_id = v_principal_id AND revoked_at IS NULL;
  RETURN FOUND;
END
$revoke_caller_delegation$;

DROP FUNCTION resolve_delegated_caller(uuid);

CREATE FUNCTION resolve_delegated_caller(p_tenant_id UUID, p_principal_id UUID, p_caller_id UUID)
RETURNS TABLE (delegation_id UUID, caller_id UUID, caller_kind TEXT)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp
AS $resolve_delegated_caller$
BEGIN
  IF p_tenant_id IS NULL OR p_principal_id IS NULL OR p_caller_id IS NULL THEN
    RAISE EXCEPTION 'explicit tenant, authenticated Principal and Caller are required'
      USING ERRCODE = '42501';
  END IF;
  -- Pre-token resolver for the trusted Rust ContextIssuer. Explicit arguments
  -- resolve and lock an active delegation; no identity GUC is installed.
  RETURN QUERY
  SELECT d.delegation_id, c.id, c.caller_kind
    FROM principal_caller_delegations d
    JOIN owner_principals p ON p.tenant_id = d.tenant_id AND p.caller_id = d.principal_id
    JOIN callers c ON c.tenant_id = d.tenant_id AND c.id = d.caller_id
   WHERE d.tenant_id = p_tenant_id AND d.principal_id = p_principal_id
     AND d.caller_id = p_caller_id AND d.revoked_at IS NULL
     AND p.disabled_at IS NULL AND c.revoked_at IS NULL
   FOR SHARE OF d, p, c;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'no active delegation for this Principal and Caller'
      USING ERRCODE = '42501';
  END IF;
END
$resolve_delegated_caller$;
ALTER FUNCTION resolve_delegated_caller(uuid, uuid, uuid) OWNER TO qembed_definer;
GRANT EXECUTE ON FUNCTION resolve_delegated_caller(uuid, uuid, uuid) TO qembed_runtime;

CREATE OR REPLACE FUNCTION resolve_object_tenant(p_tenant_id UUID, p_object_id UUID)
RETURNS UUID LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $qsa017_resolve$
  -- The caller must supply its already-authenticated tenant scope. This avoids
  -- requiring globally unique ObjectIds (and prevents this helper from becoming
  -- a cross-tenant object-existence oracle).
  SELECT tenant_id FROM objects
   WHERE tenant_id = p_tenant_id
     AND object_id = p_object_id
     AND p_tenant_id = qembed_crypto.current_tenant_id()
$qsa017_resolve$;

CREATE OR REPLACE FUNCTION sweep_stale_invocation_deliveries(
  p_stale_before TIMESTAMPTZ,
  p_limit INT
)
RETURNS TABLE (replayed_invocation_id UUID, replayed_delivery_id UUID)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $invocation_replay_sweeper$
DECLARE
  v_tenant_id UUID := qembed_crypto.current_tenant_id();
  candidate RECORD;
BEGIN
  IF v_tenant_id IS NULL THEN
    RAISE EXCEPTION 'tenant context is required for invocation recovery'
      USING ERRCODE = '42501';
  END IF;
  IF p_stale_before IS NULL OR p_stale_before > now()
     OR p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 500 THEN
    RAISE EXCEPTION 'invalid invocation recovery cutoff or batch size'
      USING ERRCODE = '22023';
  END IF;

  FOR candidate IN
    SELECT invocation.id AS invocation_id, delivery.delivery_id
      FROM object_invocations AS invocation
      JOIN outbox_messages AS delivery
        ON delivery.tenant_id = invocation.tenant_id
       AND delivery.topic = 'invocation.received'
       AND delivery.payload->>'invocation_id' = invocation.id::text
     WHERE invocation.tenant_id = v_tenant_id
       AND invocation.status = 'Received'
       AND invocation.cancel_requested_at IS NULL
       AND (invocation.lease_owner IS NULL OR invocation.lease_until <= now())
       AND COALESCE(invocation.heartbeat_at, invocation.started_at) <= p_stale_before
       AND delivery.delivered_at IS NOT NULL
       AND delivery.replay_requested_at IS NULL
       AND (delivery.lease_expires_at IS NULL OR delivery.lease_expires_at <= now())
       -- Missing provider-attempt evidence fails closed. An ambiguous or completed
       -- provider call must never be replayed by this queue-recovery path.
       AND EXISTS (
         SELECT 1
           FROM provider_call_attempts AS attempt
          WHERE attempt.tenant_id = invocation.tenant_id
            AND attempt.object_id = invocation.object_id
            AND attempt.invocation_id = invocation.id
            AND attempt.state IN ('NotStarted', 'ConfirmedNotAccepted', 'CancelledBeforeSend')
       )
     ORDER BY COALESCE(invocation.heartbeat_at, invocation.started_at), delivery.created_at
     LIMIT p_limit
     FOR UPDATE OF invocation, delivery SKIP LOCKED
  LOOP
    UPDATE outbox_messages
       SET replay_requested_at = clock_timestamp(),
           replay_reason = 'invocation_progress_deadline_expired',
           replay_count = replay_count + 1
     WHERE tenant_id = v_tenant_id
       AND delivery_id = candidate.delivery_id
       AND replay_requested_at IS NULL;

    IF FOUND THEN
      replayed_invocation_id := candidate.invocation_id;
      replayed_delivery_id := candidate.delivery_id;
      RETURN NEXT;
    END IF;
  END LOOP;
END
$invocation_replay_sweeper$;

-- Retention: fixed whitelist, per-table action (A8). Append-only tables are NOT purgeable here.

DO $legacy_policy_guard$
DECLARE r record;
BEGIN
 FOR r IN SELECT schemaname,tablename,policyname,qual,with_check FROM pg_policies
  WHERE schemaname='public' AND policyname IN ('tenant_isolation','own_tenant','ks_read','ks_write')
 LOOP
  IF concat_ws(' ',r.qual,r.with_check) ~ 'app\.(tenant_id|principal_id|caller_id)' THEN
   RAISE EXCEPTION 'legacy identity GUC remains in policy %.% (%)',
     r.schemaname,r.tablename,r.policyname;
  END IF;
 END LOOP;
END $legacy_policy_guard$;

DO $legacy_function_guard$
DECLARE r record;
BEGIN
 FOR r IN
  SELECT p.oid, p.proname
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid=p.pronamespace
   WHERE n.nspname='public'
     AND p.proname IN ('grant_caller_delegation','revoke_caller_delegation',
       'resolve_delegated_caller','resolve_object_tenant','sweep_stale_invocation_deliveries')
 LOOP
  IF pg_get_functiondef(r.oid) ~ 'app\\.(tenant_id|principal_id|caller_id)' THEN
   RAISE EXCEPTION 'legacy identity GUC remains in function %',r.proname;
  END IF;
 END LOOP;
END $legacy_function_guard$;
COMMIT;
