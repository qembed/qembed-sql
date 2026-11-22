-- Full RT-050 transaction-context setup for the minimal C verifier.
-- The trusted issuer runs outside PostgreSQL in the companion Python test.
-- The wire format matches qembed-store: qctx1:<payload-hex>:<signature-hex>.

DO $role$ BEGIN
  CREATE ROLE qembed_runtime NOLOGIN;
EXCEPTION WHEN duplicate_object THEN NULL;
END $role$;

CREATE SCHEMA qembed_crypto AUTHORIZATION CURRENT_USER;
CREATE EXTENSION qembed_context_verify WITH SCHEMA qembed_crypto;

CREATE TABLE qembed_crypto.verification_keys (
  key_id text PRIMARY KEY CHECK (length(key_id) BETWEEN 1 AND 128),
  public_key bytea NOT NULL CHECK (octet_length(public_key) = 32),
  issuer text NOT NULL,
  audience text NOT NULL,
  deployment_id text NOT NULL,
  status text NOT NULL DEFAULT 'active'
    CHECK (status IN ('active', 'retired', 'revoked')),
  activated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  retired_at timestamptz,
  verify_until timestamptz,
  revoked_at timestamptz,
  CHECK (
    (status = 'active' AND retired_at IS NULL AND verify_until IS NULL AND revoked_at IS NULL)
    OR
    (status = 'retired' AND retired_at IS NOT NULL AND verify_until > retired_at AND revoked_at IS NULL)
    OR
    (status = 'revoked' AND revoked_at IS NOT NULL)
  )
);

-- Key material and identity are immutable. Lifecycle transitions are monotonic:
-- active -> retired -> revoked, or active -> revoked for emergency response.
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
    IF NEW.status <> 'active'
       OR NEW.retired_at IS NOT NULL
       OR NEW.verify_until IS NOT NULL
       OR NEW.revoked_at IS NOT NULL THEN
      RAISE EXCEPTION 'new verification keys must start active';
    END IF;
    RETURN NEW;
  END IF;

  IF NEW.key_id IS DISTINCT FROM OLD.key_id
     OR NEW.public_key IS DISTINCT FROM OLD.public_key
     OR NEW.issuer IS DISTINCT FROM OLD.issuer
     OR NEW.audience IS DISTINCT FROM OLD.audience
     OR NEW.deployment_id IS DISTINCT FROM OLD.deployment_id
     OR NEW.activated_at IS DISTINCT FROM OLD.activated_at THEN
    RAISE EXCEPTION 'verification key identity and public material are immutable';
  END IF;

  IF NEW.status = OLD.status THEN
    RAISE EXCEPTION 'verification key lifecycle state cannot be rewritten in place';
  ELSIF OLD.status = 'active' AND NEW.status = 'retired' THEN
    IF NEW.retired_at IS NULL OR NEW.verify_until < NEW.retired_at + interval '90 seconds'
       OR NEW.revoked_at IS NOT NULL THEN
      RAISE EXCEPTION 'retirement requires at least 90 seconds of verification grace';
    END IF;
  ELSIF OLD.status = 'active' AND NEW.status = 'revoked' THEN
    IF NEW.revoked_at IS NULL OR NEW.retired_at IS NOT NULL OR NEW.verify_until IS NOT NULL THEN
      RAISE EXCEPTION 'direct revocation requires only revoked_at';
    END IF;
  ELSIF OLD.status = 'retired' AND NEW.status = 'revoked' THEN
    IF NEW.revoked_at IS NULL
       OR NEW.retired_at IS DISTINCT FROM OLD.retired_at
       OR NEW.verify_until IS DISTINCT FROM OLD.verify_until THEN
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

CREATE FUNCTION qembed_crypto.retire_verification_key(
  p_key_id text,
  p_verification_grace interval DEFAULT interval '90 seconds'
)
RETURNS timestamptz
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, qembed_crypto, pg_temp
AS $retire$
DECLARE
  v_retired_at timestamptz := clock_timestamp();
  v_verify_until timestamptz;
BEGIN
  IF p_verification_grace < interval '90 seconds'
     OR p_verification_grace > interval '1 hour' THEN
    RAISE EXCEPTION 'verification grace must be between 90 seconds and 1 hour';
  END IF;

  UPDATE qembed_crypto.verification_keys
  SET status = 'retired',
      retired_at = v_retired_at,
      verify_until = v_retired_at + p_verification_grace
  WHERE key_id = p_key_id AND status = 'active'
  RETURNING verify_until INTO v_verify_until;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'active verification key not found: %', p_key_id;
  END IF;
  RETURN v_verify_until;
END
$retire$;

CREATE FUNCTION qembed_crypto.revoke_verification_key(p_key_id text)
RETURNS timestamptz
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, qembed_crypto, pg_temp
AS $revoke$
DECLARE
  v_revoked_at timestamptz;
BEGIN
  UPDATE qembed_crypto.verification_keys
  SET status = 'revoked',
      revoked_at = clock_timestamp()
  WHERE key_id = p_key_id AND status IN ('active', 'retired')
  RETURNING revoked_at INTO v_revoked_at;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'revocable verification key not found: %', p_key_id;
  END IF;
  RETURN v_revoked_at;
END
$revoke$;

REVOKE ALL ON FUNCTION qembed_crypto.retire_verification_key(text, interval) FROM PUBLIC;
REVOKE ALL ON FUNCTION qembed_crypto.revoke_verification_key(text) FROM PUBLIC;

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
  IF v_key.status = 'revoked'
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

REVOKE ALL ON SCHEMA qembed_crypto FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA qembed_crypto FROM PUBLIC, qembed_runtime;
REVOKE ALL ON FUNCTION qembed_crypto.verified_context(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION qembed_crypto.current_tenant_id() FROM PUBLIC;
REVOKE ALL ON FUNCTION qembed_crypto.current_principal_id() FROM PUBLIC;
REVOKE ALL ON FUNCTION qembed_crypto.current_caller_id() FROM PUBLIC;
GRANT USAGE ON SCHEMA qembed_crypto TO qembed_runtime;
GRANT EXECUTE ON FUNCTION qembed_crypto.verified_context(text) TO qembed_runtime;
GRANT EXECUTE ON FUNCTION qembed_crypto.current_tenant_id() TO qembed_runtime;
GRANT EXECUTE ON FUNCTION qembed_crypto.current_principal_id() TO qembed_runtime;
GRANT EXECUTE ON FUNCTION qembed_crypto.current_caller_id() TO qembed_runtime;

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
