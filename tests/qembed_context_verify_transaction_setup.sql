-- Full RT-050 transaction-context setup for the minimal C verifier.
-- The trusted issuer runs outside PostgreSQL in the companion Python test.
-- The wire format matches qembed-store: qctx1:<payload-hex>:<signature-hex>.

DO $roles$ BEGIN
  CREATE ROLE qembed_runtime NOLOGIN;
EXCEPTION WHEN duplicate_object THEN NULL;
END $roles$;

DO $roles$ BEGIN
  CREATE ROLE qembed_key_registry_owner NOLOGIN;
EXCEPTION WHEN duplicate_object THEN NULL;
END $roles$;

DO $roles$ BEGIN
  CREATE ROLE qembed_key_control_plane LOGIN NOINHERIT;
EXCEPTION WHEN duplicate_object THEN NULL;
END $roles$;

CREATE SCHEMA qembed_crypto AUTHORIZATION CURRENT_USER;
GRANT USAGE, CREATE ON SCHEMA qembed_crypto TO qembed_key_registry_owner;
CREATE EXTENSION qembed_context_verify WITH SCHEMA qembed_crypto;

CREATE TABLE qembed_crypto.verification_keys (
  key_id text PRIMARY KEY CHECK (length(key_id) BETWEEN 1 AND 128),
  public_key bytea NOT NULL CHECK (octet_length(public_key) = 32),
  issuer text NOT NULL,
  audience text NOT NULL,
  deployment_id text NOT NULL,
  status text NOT NULL DEFAULT 'staged'
    CHECK (status IN ('staged', 'active', 'retired', 'revoked')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  activated_at timestamptz,
  retired_at timestamptz,
  verify_until timestamptz,
  revoked_at timestamptz,
  CHECK (
    (status = 'staged' AND activated_at IS NULL AND retired_at IS NULL AND verify_until IS NULL AND revoked_at IS NULL)
    OR
    (status = 'active' AND activated_at IS NOT NULL AND retired_at IS NULL AND verify_until IS NULL AND revoked_at IS NULL)
    OR
    (status = 'retired' AND activated_at IS NOT NULL AND retired_at IS NOT NULL AND verify_until > retired_at AND revoked_at IS NULL)
    OR
    (status = 'revoked' AND revoked_at IS NOT NULL)
  )
);

CREATE TABLE qembed_crypto.key_lifecycle_audit (
  event_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  request_id uuid NOT NULL UNIQUE,
  key_id text NOT NULL REFERENCES qembed_crypto.verification_keys(key_id),
  operation text NOT NULL CHECK (operation IN ('stage', 'activate', 'retire', 'revoke')),
  prior_state text,
  new_state text NOT NULL,
  actor_subject text NOT NULL CHECK (length(actor_subject) BETWEEN 1 AND 256),
  approver_subject text,
  reason text NOT NULL CHECK (length(reason) BETWEEN 1 AND 1024),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

-- Key identity/material is immutable. Production lifecycle is staged -> active
-- -> retired -> revoked, with staged/active -> revoked emergency paths.
CREATE FUNCTION qembed_crypto.guard_verification_key_lifecycle()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, qembed_crypto, pg_temp
AS $guard$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'verification keys are retained for audit; deletion is forbidden';
  END IF;

  IF TG_OP = 'INSERT' THEN
    IF NEW.status <> 'staged'
       OR NEW.activated_at IS NOT NULL
       OR NEW.retired_at IS NOT NULL
       OR NEW.verify_until IS NOT NULL
       OR NEW.revoked_at IS NOT NULL THEN
      RAISE EXCEPTION 'new verification keys must start staged';
    END IF;
    RETURN NEW;
  END IF;

  IF NEW.key_id IS DISTINCT FROM OLD.key_id
     OR NEW.public_key IS DISTINCT FROM OLD.public_key
     OR NEW.issuer IS DISTINCT FROM OLD.issuer
     OR NEW.audience IS DISTINCT FROM OLD.audience
     OR NEW.deployment_id IS DISTINCT FROM OLD.deployment_id
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'verification key identity and public material are immutable';
  END IF;

  IF NEW.status = OLD.status THEN
    RAISE EXCEPTION 'verification key lifecycle state cannot be rewritten in place';
  ELSIF OLD.status = 'staged' AND NEW.status = 'active' THEN
    IF NEW.activated_at IS NULL OR NEW.retired_at IS NOT NULL
       OR NEW.verify_until IS NOT NULL OR NEW.revoked_at IS NOT NULL THEN
      RAISE EXCEPTION 'activation requires only activated_at';
    END IF;
  ELSIF OLD.status = 'staged' AND NEW.status = 'revoked' THEN
    IF NEW.activated_at IS NOT NULL OR NEW.retired_at IS NOT NULL
       OR NEW.verify_until IS NOT NULL OR NEW.revoked_at IS NULL THEN
      RAISE EXCEPTION 'staged-key revocation requires only revoked_at';
    END IF;
  ELSIF OLD.status = 'active' AND NEW.status = 'retired' THEN
    IF NEW.activated_at IS DISTINCT FROM OLD.activated_at
       OR NEW.retired_at IS NULL OR NEW.verify_until IS NULL
       OR NEW.verify_until < NEW.retired_at + interval '120 seconds'
       OR NEW.verify_until > NEW.retired_at + interval '1 hour'
       OR NEW.revoked_at IS NOT NULL THEN
      RAISE EXCEPTION 'retirement requires a 120-second to 1-hour verification grace';
    END IF;
  ELSIF OLD.status = 'active' AND NEW.status = 'revoked' THEN
    IF NEW.activated_at IS DISTINCT FROM OLD.activated_at
       OR NEW.retired_at IS NOT NULL OR NEW.verify_until IS NOT NULL
       OR NEW.revoked_at IS NULL THEN
      RAISE EXCEPTION 'active-key emergency revocation has invalid timestamps';
    END IF;
  ELSIF OLD.status = 'retired' AND NEW.status = 'revoked' THEN
    IF NEW.activated_at IS DISTINCT FROM OLD.activated_at
       OR NEW.retired_at IS DISTINCT FROM OLD.retired_at
       OR NEW.verify_until IS DISTINCT FROM OLD.verify_until
       OR NEW.revoked_at IS NULL THEN
      RAISE EXCEPTION 'revocation must preserve retirement audit timestamps';
    END IF;
  ELSE
    RAISE EXCEPTION 'invalid verification key lifecycle transition: % -> %',
      OLD.status, NEW.status;
  END IF;

  RETURN NEW;
END
$guard$;

CREATE TRIGGER verification_key_lifecycle_guard
BEFORE INSERT OR UPDATE OR DELETE ON qembed_crypto.verification_keys
FOR EACH ROW EXECUTE FUNCTION qembed_crypto.guard_verification_key_lifecycle();

CREATE FUNCTION qembed_crypto.prevent_key_audit_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, qembed_crypto, pg_temp
AS $audit_guard$
BEGIN
  RAISE EXCEPTION 'key lifecycle audit is append-only';
END
$audit_guard$;

CREATE TRIGGER key_lifecycle_audit_append_only
BEFORE UPDATE OR DELETE ON qembed_crypto.key_lifecycle_audit
FOR EACH ROW EXECUTE FUNCTION qembed_crypto.prevent_key_audit_mutation();

CREATE FUNCTION qembed_crypto.stage_verification_key(
  p_key_id text,
  p_public_key bytea,
  p_issuer text,
  p_audience text,
  p_deployment_id text,
  p_actor_subject text,
  p_request_id uuid,
  p_reason text
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, qembed_crypto, pg_temp
AS $stage$
DECLARE
  v_operation text;
  v_existing_key_id text;
  v_existing_actor text;
  v_existing_reason text;
  v_existing_public_key bytea;
  v_existing_issuer text;
  v_existing_audience text;
  v_existing_deployment text;
BEGIN
  IF session_user <> 'qembed_key_control_plane' THEN
    RAISE EXCEPTION 'key management requires the dedicated control-plane identity';
  END IF;
  IF p_request_id IS NULL OR p_actor_subject IS NULL OR btrim(p_actor_subject) = ''
     OR p_reason IS NULL OR btrim(p_reason) = '' THEN
    RAISE EXCEPTION 'request ID, actor subject and reason are required';
  END IF;

  SELECT a.operation, a.key_id, a.actor_subject, a.reason,
         k.public_key, k.issuer, k.audience, k.deployment_id
  INTO v_operation, v_existing_key_id, v_existing_actor, v_existing_reason,
       v_existing_public_key, v_existing_issuer, v_existing_audience, v_existing_deployment
  FROM qembed_crypto.key_lifecycle_audit AS a
  JOIN qembed_crypto.verification_keys AS k USING (key_id)
  WHERE a.request_id = p_request_id;
  IF FOUND THEN
    IF v_operation = 'stage' AND v_existing_key_id = p_key_id
       AND v_existing_actor IS NOT DISTINCT FROM p_actor_subject
       AND v_existing_reason IS NOT DISTINCT FROM p_reason
       AND v_existing_public_key IS NOT DISTINCT FROM p_public_key
       AND v_existing_issuer IS NOT DISTINCT FROM p_issuer
       AND v_existing_audience IS NOT DISTINCT FROM p_audience
       AND v_existing_deployment IS NOT DISTINCT FROM p_deployment_id THEN
      RETURN;
    END IF;
    RAISE EXCEPTION 'request ID was already used with a different key operation or payload';
  END IF;

  INSERT INTO qembed_crypto.verification_keys
    (key_id, public_key, issuer, audience, deployment_id, status)
  VALUES
    (p_key_id, p_public_key, p_issuer, p_audience, p_deployment_id, 'staged');

  INSERT INTO qembed_crypto.key_lifecycle_audit
    (request_id, key_id, operation, prior_state, new_state, actor_subject, reason)
  VALUES
    (p_request_id, p_key_id, 'stage', NULL, 'staged', p_actor_subject, p_reason);
END
$stage$;

CREATE FUNCTION qembed_crypto.activate_verification_key(
  p_key_id text,
  p_actor_subject text,
  p_approver_subject text,
  p_request_id uuid,
  p_reason text
)
RETURNS timestamptz
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, qembed_crypto, pg_temp
AS $activate$
DECLARE
  v_operation text;
  v_existing_key_id text;
  v_existing_actor text;
  v_existing_approver text;
  v_existing_reason text;
  v_activated_at timestamptz;
  v_old_state text;
BEGIN
  IF session_user <> 'qembed_key_control_plane' THEN
    RAISE EXCEPTION 'key management requires the dedicated control-plane identity';
  END IF;
  IF p_request_id IS NULL OR p_actor_subject IS NULL OR btrim(p_actor_subject) = ''
     OR p_approver_subject IS NULL OR btrim(p_approver_subject) = ''
     OR p_actor_subject = p_approver_subject
     OR p_reason IS NULL OR btrim(p_reason) = '' THEN
    RAISE EXCEPTION 'distinct operator and approver, request ID and reason are required';
  END IF;

  SELECT operation, key_id, actor_subject, approver_subject, reason
  INTO v_operation, v_existing_key_id, v_existing_actor, v_existing_approver, v_existing_reason
  FROM qembed_crypto.key_lifecycle_audit
  WHERE request_id = p_request_id;
  IF FOUND THEN
    IF v_operation = 'activate' AND v_existing_key_id = p_key_id
       AND v_existing_actor IS NOT DISTINCT FROM p_actor_subject
       AND v_existing_approver IS NOT DISTINCT FROM p_approver_subject
       AND v_existing_reason IS NOT DISTINCT FROM p_reason THEN
      SELECT activated_at INTO v_activated_at
      FROM qembed_crypto.verification_keys WHERE key_id = p_key_id;
      RETURN v_activated_at;
    END IF;
    RAISE EXCEPTION 'request ID was already used with a different key operation or payload';
  END IF;

  SELECT status INTO v_old_state
  FROM qembed_crypto.verification_keys
  WHERE key_id = p_key_id
  FOR UPDATE;
  IF NOT FOUND OR v_old_state <> 'staged' THEN
    RAISE EXCEPTION 'staged verification key not found: %', p_key_id;
  END IF;

  UPDATE qembed_crypto.verification_keys
  SET status = 'active', activated_at = clock_timestamp()
  WHERE key_id = p_key_id
  RETURNING activated_at INTO v_activated_at;

  INSERT INTO qembed_crypto.key_lifecycle_audit
    (request_id, key_id, operation, prior_state, new_state,
     actor_subject, approver_subject, reason)
  VALUES
    (p_request_id, p_key_id, 'activate', 'staged', 'active',
     p_actor_subject, p_approver_subject, p_reason);

  RETURN v_activated_at;
END
$activate$;

CREATE FUNCTION qembed_crypto.retire_verification_key(
  p_key_id text,
  p_verification_grace interval,
  p_actor_subject text,
  p_approver_subject text,
  p_request_id uuid,
  p_reason text
)
RETURNS timestamptz
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, qembed_crypto, pg_temp
AS $retire$
DECLARE
  v_operation text;
  v_existing_key_id text;
  v_existing_actor text;
  v_existing_approver text;
  v_existing_reason text;
  v_existing_grace interval;
  v_retired_at timestamptz := clock_timestamp();
  v_verify_until timestamptz;
  v_old_state text;
BEGIN
  IF session_user <> 'qembed_key_control_plane' THEN
    RAISE EXCEPTION 'key management requires the dedicated control-plane identity';
  END IF;
  IF p_request_id IS NULL OR p_actor_subject IS NULL OR btrim(p_actor_subject) = ''
     OR p_approver_subject IS NULL OR btrim(p_approver_subject) = ''
     OR p_actor_subject = p_approver_subject
     OR p_reason IS NULL OR btrim(p_reason) = '' THEN
    RAISE EXCEPTION 'distinct operator and approver, request ID and reason are required';
  END IF;
  IF p_verification_grace < interval '120 seconds'
     OR p_verification_grace > interval '1 hour' THEN
    RAISE EXCEPTION 'verification grace must be between 120 seconds and 1 hour';
  END IF;

  SELECT a.operation, a.key_id, a.actor_subject, a.approver_subject, a.reason,
         k.verify_until - k.retired_at
  INTO v_operation, v_existing_key_id, v_existing_actor, v_existing_approver,
       v_existing_reason, v_existing_grace
  FROM qembed_crypto.key_lifecycle_audit AS a
  JOIN qembed_crypto.verification_keys AS k USING (key_id)
  WHERE a.request_id = p_request_id;
  IF FOUND THEN
    IF v_operation = 'retire' AND v_existing_key_id = p_key_id
       AND v_existing_actor IS NOT DISTINCT FROM p_actor_subject
       AND v_existing_approver IS NOT DISTINCT FROM p_approver_subject
       AND v_existing_reason IS NOT DISTINCT FROM p_reason
       AND v_existing_grace IS NOT DISTINCT FROM p_verification_grace THEN
      SELECT verify_until INTO v_verify_until
      FROM qembed_crypto.verification_keys WHERE key_id = p_key_id;
      RETURN v_verify_until;
    END IF;
    RAISE EXCEPTION 'request ID was already used with a different key operation or payload';
  END IF;

  SELECT status INTO v_old_state
  FROM qembed_crypto.verification_keys
  WHERE key_id = p_key_id
  FOR UPDATE;
  IF NOT FOUND OR v_old_state <> 'active' THEN
    RAISE EXCEPTION 'active verification key not found: %', p_key_id;
  END IF;

  v_verify_until := v_retired_at + p_verification_grace;
  UPDATE qembed_crypto.verification_keys
  SET status = 'retired',
      retired_at = v_retired_at,
      verify_until = v_verify_until
  WHERE key_id = p_key_id;

  INSERT INTO qembed_crypto.key_lifecycle_audit
    (request_id, key_id, operation, prior_state, new_state,
     actor_subject, approver_subject, reason)
  VALUES
    (p_request_id, p_key_id, 'retire', 'active', 'retired',
     p_actor_subject, p_approver_subject, p_reason);

  RETURN v_verify_until;
END
$retire$;

CREATE FUNCTION qembed_crypto.revoke_verification_key(
  p_key_id text,
  p_actor_subject text,
  p_request_id uuid,
  p_reason text
)
RETURNS timestamptz
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, qembed_crypto, pg_temp
AS $revoke$
DECLARE
  v_operation text;
  v_existing_key_id text;
  v_existing_actor text;
  v_existing_reason text;
  v_revoked_at timestamptz := clock_timestamp();
  v_old_state text;
BEGIN
  IF session_user <> 'qembed_key_control_plane' THEN
    RAISE EXCEPTION 'key management requires the dedicated control-plane identity';
  END IF;
  IF p_request_id IS NULL OR p_actor_subject IS NULL OR btrim(p_actor_subject) = ''
     OR p_reason IS NULL OR btrim(p_reason) = '' THEN
    RAISE EXCEPTION 'break-glass actor, incident reference and request ID are required';
  END IF;

  SELECT operation, key_id, actor_subject, reason
  INTO v_operation, v_existing_key_id, v_existing_actor, v_existing_reason
  FROM qembed_crypto.key_lifecycle_audit
  WHERE request_id = p_request_id;
  IF FOUND THEN
    IF v_operation = 'revoke' AND v_existing_key_id = p_key_id
       AND v_existing_actor IS NOT DISTINCT FROM p_actor_subject
       AND v_existing_reason IS NOT DISTINCT FROM p_reason THEN
      SELECT revoked_at INTO v_revoked_at
      FROM qembed_crypto.verification_keys WHERE key_id = p_key_id;
      RETURN v_revoked_at;
    END IF;
    RAISE EXCEPTION 'request ID was already used with a different key operation or payload';
  END IF;

  SELECT status INTO v_old_state
  FROM qembed_crypto.verification_keys
  WHERE key_id = p_key_id
  FOR UPDATE;
  IF NOT FOUND OR v_old_state NOT IN ('staged', 'active', 'retired') THEN
    RAISE EXCEPTION 'revocable verification key not found: %', p_key_id;
  END IF;

  UPDATE qembed_crypto.verification_keys
  SET status = 'revoked', revoked_at = v_revoked_at
  WHERE key_id = p_key_id;

  INSERT INTO qembed_crypto.key_lifecycle_audit
    (request_id, key_id, operation, prior_state, new_state, actor_subject, reason)
  VALUES
    (p_request_id, p_key_id, 'revoke', v_old_state, 'revoked',
     p_actor_subject, p_reason);

  RETURN v_revoked_at;
END
$revoke$;

-- Stable for one statement: statement_timestamp and the already-established XID
-- keep the RLS scalar subquery eligible for a single InitPlan evaluation.
CREATE FUNCTION qembed_crypto.verified_context(p_token text)
RETURNS jsonb
LANGUAGE plpgsql STABLE
SECURITY DEFINER
SET search_path = pg_catalog, qembed_crypto, pg_temp
AS $verify$
DECLARE
  v_payload_hex text;
  v_signature_hex text;
  v_payload bytea;
  v_signature bytea;
  v_untrusted_claims jsonb;
  v_claims jsonb;
  v_key record;
  v_key_id text;
  v_database_oid text;
  v_now timestamptz := statement_timestamp();
  v_issued_at timestamptz;
  v_expires_at timestamptz;
  v_required_claim text;
  v_claim_count integer;
BEGIN
  -- Reject unsupported envelope versions, extra fields, uppercase/non-hex
  -- encodings, malformed lengths and payloads above the C verifier's 8 KiB cap.
  IF p_token IS NULL OR length(p_token) > 16526
     OR p_token !~ '^qctx1:[0-9a-f]+:[0-9a-f]{128}$' THEN
    RETURN NULL;
  END IF;

  v_payload_hex := split_part(p_token, ':', 2);
  v_signature_hex := split_part(p_token, ':', 3);
  IF length(v_payload_hex) = 0 OR length(v_payload_hex) % 2 <> 0
     OR length(v_payload_hex) > 16384 THEN
    RETURN NULL;
  END IF;

  v_payload := decode(v_payload_hex, 'hex');
  v_signature := decode(v_signature_hex, 'hex');
  IF octet_length(v_payload) = 0 OR octet_length(v_payload) > 8192
     OR octet_length(v_signature) <> 64 THEN
    RETURN NULL;
  END IF;

  -- key_id is an untrusted lookup selector only. No claim is trusted until
  -- the signature over the original payload bytes has been verified below.
  v_untrusted_claims := convert_from(v_payload, 'UTF8')::jsonb;
  IF jsonb_typeof(v_untrusted_claims) <> 'object'
     OR jsonb_typeof(v_untrusted_claims->'key_id') <> 'string' THEN
    RETURN NULL;
  END IF;
  v_key_id := v_untrusted_claims->>'key_id';

  SELECT * INTO v_key
  FROM qembed_crypto.verification_keys
  WHERE key_id = v_key_id;
  IF NOT FOUND THEN
    RETURN NULL;
  END IF;

  IF NOT qembed_crypto.qembed_context_verify_detached(
    v_signature, v_payload, v_key.public_key
  ) THEN
    RETURN NULL;
  END IF;

  -- Only after signature verification do we treat the parsed claims as trusted.
  v_claims := convert_from(v_payload, 'UTF8')::jsonb;
  IF jsonb_typeof(v_claims) <> 'object' THEN
    RETURN NULL;
  END IF;
  SELECT count(*) INTO v_claim_count FROM jsonb_object_keys(v_claims);
  IF v_claim_count <> 14 THEN
    -- Version 1 has an exact claim set; unknown fields fail closed.
    RETURN NULL;
  END IF;

  FOREACH v_required_claim IN ARRAY ARRAY[
    'version', 'tenant_id', 'principal_id', 'caller_id', 'backend_pid',
    'transaction_id', 'database_oid', 'deployment_id', 'issuer', 'audience',
    'key_id', 'issued_at', 'expires_at', 'nonce'
  ] LOOP
    IF jsonb_typeof(v_claims->v_required_claim) <> 'string' THEN
      RETURN NULL;
    END IF;
  END LOOP;

  IF v_claims->>'version' <> '1'
     OR v_claims->>'tenant_id' !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
     OR v_claims->>'principal_id' !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
     OR v_claims->>'caller_id' !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
     OR v_claims->>'nonce' !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
     OR v_claims->>'key_id' IS DISTINCT FROM v_key.key_id THEN
    RETURN NULL;
  END IF;

  SELECT oid::text INTO STRICT v_database_oid
  FROM pg_database
  WHERE datname = current_database();

  v_issued_at := (v_claims->>'issued_at')::timestamptz;
  v_expires_at := (v_claims->>'expires_at')::timestamptz;

  IF v_claims->>'issuer' IS DISTINCT FROM v_key.issuer
     OR v_claims->>'audience' IS DISTINCT FROM v_key.audience
     OR v_claims->>'deployment_id' IS DISTINCT FROM v_key.deployment_id
     OR v_claims->>'database_oid' IS DISTINCT FROM v_database_oid
     OR v_claims->>'backend_pid' IS DISTINCT FROM pg_backend_pid()::text
     OR v_claims->>'transaction_id' IS DISTINCT FROM pg_current_xact_id()::text
     OR v_issued_at > v_now + interval '30 seconds'
     OR v_expires_at <= v_now
     OR v_expires_at <= v_issued_at
     OR v_expires_at - v_issued_at > interval '60 seconds' THEN
    RETURN NULL;
  END IF;

  -- Active keys may verify tokens issued after activation. Retired keys are
  -- verification-only until the grace deadline, and only for tokens issued
  -- before retirement whose full lifetime fits inside that deadline.
  -- Revocation is immediate and invalidates even otherwise-live tokens.
  IF v_key.status IN ('staged', 'revoked')
     OR (v_key.status = 'active' AND v_issued_at < v_key.activated_at)
     OR (v_key.status = 'retired' AND (
       v_issued_at > v_key.retired_at
       OR v_now >= v_key.verify_until
       OR v_expires_at > v_key.verify_until
     )) THEN
    RETURN NULL;
  END IF;

  RETURN v_claims;
EXCEPTION WHEN OTHERS THEN
  -- Malformed tokens and invalid claim encodings fail closed.
  RETURN NULL;
END
$verify$;

CREATE FUNCTION qembed_crypto.current_tenant_id()
RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, qembed_crypto, pg_temp
AS $tenant$
  SELECT (qembed_crypto.verified_context(
    current_setting('app.context_token', true)
  )->>'tenant_id')::uuid
$tenant$;

CREATE FUNCTION qembed_crypto.current_principal_id()
RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, qembed_crypto, pg_temp
AS $principal$
  SELECT (qembed_crypto.verified_context(
    current_setting('app.context_token', true)
  )->>'principal_id')::uuid
$principal$;

CREATE FUNCTION qembed_crypto.current_caller_id()
RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, qembed_crypto, pg_temp
AS $caller$
  SELECT (qembed_crypto.verified_context(
    current_setting('app.context_token', true)
  )->>'caller_id')::uuid
$caller$;

-- Transfer registry and SECURITY DEFINER ownership to a dedicated NOLOGIN role.
ALTER TABLE qembed_crypto.verification_keys OWNER TO qembed_key_registry_owner;
ALTER TABLE qembed_crypto.key_lifecycle_audit OWNER TO qembed_key_registry_owner;
ALTER FUNCTION qembed_crypto.guard_verification_key_lifecycle() OWNER TO qembed_key_registry_owner;
ALTER FUNCTION qembed_crypto.prevent_key_audit_mutation() OWNER TO qembed_key_registry_owner;
ALTER FUNCTION qembed_crypto.stage_verification_key(text, bytea, text, text, text, text, uuid, text)
  OWNER TO qembed_key_registry_owner;
ALTER FUNCTION qembed_crypto.activate_verification_key(text, text, text, uuid, text)
  OWNER TO qembed_key_registry_owner;
ALTER FUNCTION qembed_crypto.retire_verification_key(text, interval, text, text, uuid, text)
  OWNER TO qembed_key_registry_owner;
ALTER FUNCTION qembed_crypto.revoke_verification_key(text, text, uuid, text)
  OWNER TO qembed_key_registry_owner;
ALTER FUNCTION qembed_crypto.verified_context(text) OWNER TO qembed_key_registry_owner;
ALTER FUNCTION qembed_crypto.current_tenant_id() OWNER TO qembed_key_registry_owner;
ALTER FUNCTION qembed_crypto.current_principal_id() OWNER TO qembed_key_registry_owner;

ALTER FUNCTION qembed_crypto.current_caller_id() OWNER TO qembed_key_registry_owner;

-- The registry owner is the only principal allowed to invoke the low-level C verifier.
GRANT EXECUTE ON FUNCTION qembed_crypto.qembed_context_verify_detached(bytea, bytea, bytea)
  TO qembed_key_registry_owner;

REVOKE ALL ON SCHEMA qembed_crypto FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA qembed_crypto
  FROM PUBLIC, qembed_runtime, qembed_key_control_plane;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA qembed_crypto
  FROM PUBLIC, qembed_runtime, qembed_key_control_plane;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA qembed_crypto FROM PUBLIC;

GRANT USAGE ON SCHEMA qembed_crypto TO qembed_runtime, qembed_key_control_plane;
GRANT EXECUTE ON FUNCTION qembed_crypto.verified_context(text) TO qembed_runtime;
GRANT EXECUTE ON FUNCTION qembed_crypto.current_tenant_id() TO qembed_runtime;
GRANT EXECUTE ON FUNCTION qembed_crypto.current_principal_id() TO qembed_runtime;
GRANT EXECUTE ON FUNCTION qembed_crypto.current_caller_id() TO qembed_runtime;
GRANT EXECUTE ON FUNCTION qembed_crypto.stage_verification_key(text, bytea, text, text, text, text, uuid, text)
  TO qembed_key_control_plane;
GRANT EXECUTE ON FUNCTION qembed_crypto.activate_verification_key(text, text, text, uuid, text)
  TO qembed_key_control_plane;
GRANT EXECUTE ON FUNCTION qembed_crypto.retire_verification_key(text, interval, text, text, uuid, text)
  TO qembed_key_control_plane;
GRANT EXECUTE ON FUNCTION qembed_crypto.revoke_verification_key(text, text, uuid, text)
  TO qembed_key_control_plane;

CREATE TABLE qembed_crypto.tenant_rows (
  tenant_id uuid NOT NULL,
  row_id integer NOT NULL
);
INSERT INTO qembed_crypto.tenant_rows
SELECT CASE WHEN n <= 5
  THEN '10000000-0000-0000-0000-000000000001'::uuid
  ELSE '10000000-0000-0000-0000-000000000002'::uuid END, n
FROM generate_series(1, 10) AS g(n);
ALTER TABLE qembed_crypto.tenant_rows ENABLE ROW LEVEL SECURITY;
ALTER TABLE qembed_crypto.tenant_rows FORCE ROW LEVEL SECURITY;
CREATE POLICY signed_tenant_policy ON qembed_crypto.tenant_rows
  USING (tenant_id = (SELECT qembed_crypto.current_tenant_id()));
GRANT SELECT ON qembed_crypto.tenant_rows TO qembed_runtime;
