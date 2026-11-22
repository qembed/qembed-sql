-- Full RT-050 transaction-context setup for the minimal C verifier.
-- The trusted issuer runs outside PostgreSQL in the companion Python test.

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

CREATE FUNCTION qembed_crypto.verified_context(p_payload bytea, p_signature bytea)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, qembed_crypto, pg_temp
AS $verify$
DECLARE
  v_claims jsonb;
  v_key record;
  v_database_oid text;
  v_now timestamptz := clock_timestamp();
BEGIN
  IF p_payload IS NULL OR p_signature IS NULL
     OR octet_length(p_payload) = 0 OR octet_length(p_payload) > 8192 THEN
    RETURN NULL;
  END IF;
  v_claims := convert_from(p_payload, 'UTF8')::jsonb;
  IF jsonb_typeof(v_claims) <> 'object' OR v_claims->>'key_id' IS NULL
     OR v_claims->>'issued_at' IS NULL OR v_claims->>'expires_at' IS NULL THEN
    RETURN NULL;
  END IF;
  SELECT * INTO v_key FROM qembed_crypto.verification_keys
    WHERE key_id = v_claims->>'key_id';
  IF NOT FOUND THEN RETURN NULL; END IF;
  IF NOT qembed_crypto.qembed_context_verify_detached(
    p_signature, p_payload, v_key.public_key
  ) THEN RETURN NULL; END IF;

  SELECT oid::text INTO STRICT v_database_oid FROM pg_database
    WHERE datname = current_database();
  IF v_claims->>'issuer' IS DISTINCT FROM v_key.issuer
     OR v_claims->>'audience' IS DISTINCT FROM v_key.audience
     OR v_claims->>'deployment_id' IS DISTINCT FROM v_key.deployment_id
     OR v_claims->>'database_oid' IS DISTINCT FROM v_database_oid
     OR v_claims->>'backend_pid' IS DISTINCT FROM pg_backend_pid()::text
     OR v_claims->>'transaction_id' IS DISTINCT FROM pg_current_xact_id()::text
     OR (v_claims->>'issued_at')::timestamptz > v_now + interval '30 seconds'
     OR (v_claims->>'expires_at')::timestamptz <= v_now
     OR (v_claims->>'expires_at')::timestamptz <= (v_claims->>'issued_at')::timestamptz
     OR (v_claims->>'expires_at')::timestamptz -
          (v_claims->>'issued_at')::timestamptz > interval '60 seconds' THEN
    RETURN NULL;
  END IF;
  RETURN v_claims;
EXCEPTION WHEN OTHERS THEN
  RETURN NULL;
END
$verify$;

CREATE FUNCTION qembed_crypto.current_tenant_id()
RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, qembed_crypto, pg_temp
AS $tenant$
  SELECT (qembed_crypto.verified_context(
    decode(current_setting('app.context_payload', true), 'hex'),
    decode(current_setting('app.context_signature', true), 'hex')
  )->>'tenant_id')::uuid
$tenant$;

REVOKE ALL ON SCHEMA qembed_crypto FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA qembed_crypto FROM PUBLIC, qembed_runtime;
REVOKE ALL ON FUNCTION qembed_crypto.verified_context(bytea, bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION qembed_crypto.current_tenant_id() FROM PUBLIC;
GRANT USAGE ON SCHEMA qembed_crypto TO qembed_runtime;
GRANT EXECUTE ON FUNCTION qembed_crypto.verified_context(bytea, bytea) TO qembed_runtime;
GRANT EXECUTE ON FUNCTION qembed_crypto.current_tenant_id() TO qembed_runtime;

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
