-- Full RT-050 transaction-context setup for the minimal C verifier.
-- The trusted issuer runs outside PostgreSQL in the companion Python test.
-- The wire format matches qembed-store: qctx1:<payload-hex>:<signature-hex>.

DO $role$ BEGIN
  CREATE ROLE qembed_runtime NOLOGIN;
EXCEPTION WHEN duplicate_object THEN NULL;
END $role$;

CREATE SCHEMA qembed_crypto AUTHORIZATION postgres;
CREATE EXTENSION qembed_context_verify WITH SCHEMA qembed_crypto;

CREATE TABLE qembed_crypto.verification_keys (
  key_id text PRIMARY KEY,
  public_key bytea NOT NULL,
  issuer text NOT NULL,
  audience text NOT NULL,
  deployment_id text NOT NULL
);

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
     OR v_claims->>'tenant_id' !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
     OR v_claims->>'principal_id' !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
     OR v_claims->>'caller_id' !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}
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

     OR v_claims->>'nonce' !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}
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
