-- RT-050 prototype only. No production DDL or RLS integration.
-- Tests detached-signature verification and binding to backend, transaction,
-- database and provisioned deployment identity.

CREATE ROLE qembed_runtime NOLOGIN;
CREATE SCHEMA qsa003_probe;
CREATE TABLE qsa003_probe.verification_keys (
  key_id text PRIMARY KEY, public_key bytea NOT NULL, issuer text NOT NULL,
  audience text NOT NULL, deployment_id text NOT NULL
);
CREATE TABLE qsa003_probe.probe_tokens (
  test_case text PRIMARY KEY, payload bytea NOT NULL, signature bytea NOT NULL
);
CREATE TEMP TABLE qsa003_issuer_material (public_key bytea NOT NULL, secret_key bytea NOT NULL);
CREATE TEMP TABLE qsa003_expected (claims jsonb NOT NULL);
GRANT SELECT ON pg_temp.qsa003_expected TO qembed_runtime;

DO $$
DECLARE v_pair record;
BEGIN
  SELECT * INTO STRICT v_pair FROM pgsodium.crypto_sign_new_keypair();
  INSERT INTO pg_temp.qsa003_issuer_material VALUES (v_pair.public, v_pair.secret);
  INSERT INTO qsa003_probe.verification_keys
    (key_id, public_key, issuer, audience, deployment_id)
  VALUES ('probe-key-1', v_pair.public, 'urn:qembed:context-issuer:probe',
    'urn:qembed:postgres:deployment:probe-1:database:' ||
      (SELECT oid::text FROM pg_database WHERE datname = current_database()),
    'probe-deployment-1');
END
$$;

CREATE FUNCTION qsa003_probe.verified_context(p_payload bytea, p_signature bytea)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pgsodium, qsa003_probe, pg_temp
AS $$
DECLARE
  v_claims jsonb;
  v_key record;
  v_database_oid text;
  v_now timestamptz := clock_timestamp();
BEGIN
  IF p_payload IS NULL OR p_signature IS NULL OR octet_length(p_payload) = 0
     OR octet_length(p_payload) > 8192 THEN RETURN NULL; END IF;
  v_claims := convert_from(p_payload, 'UTF8')::jsonb;
  IF jsonb_typeof(v_claims) <> 'object' OR v_claims->>'key_id' IS NULL THEN
    RETURN NULL;
  END IF;
  SELECT * INTO v_key FROM qsa003_probe.verification_keys
    WHERE key_id = v_claims->>'key_id';
  IF NOT FOUND THEN RETURN NULL; END IF;
  IF NOT pgsodium.crypto_sign_verify_detached(p_signature, p_payload, v_key.public_key) THEN
    RETURN NULL;
  END IF;
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
$$;

REVOKE ALL ON SCHEMA qsa003_probe FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA qsa003_probe FROM PUBLIC, qembed_runtime;
REVOKE ALL ON FUNCTION qsa003_probe.verified_context(bytea, bytea) FROM PUBLIC;
GRANT USAGE ON SCHEMA qsa003_probe TO qembed_runtime;
GRANT EXECUTE ON FUNCTION qsa003_probe.verified_context(bytea, bytea) TO qembed_runtime;
GRANT SELECT ON qsa003_probe.probe_tokens TO qembed_runtime;

BEGIN;
DO $$
DECLARE
  v_material record;
  v_base_claims jsonb;
  v_claims jsonb;
  v_payload bytea;
  v_signature bytea;
  v_db_oid text;
  v_audience text;
BEGIN
  SELECT * INTO STRICT v_material FROM pg_temp.qsa003_issuer_material;
  SELECT oid::text INTO STRICT v_db_oid FROM pg_database WHERE datname = current_database();
  v_audience := 'urn:qembed:postgres:deployment:probe-1:database:' || v_db_oid;
  v_base_claims := jsonb_build_object(
    'tenant_id', '10000000-0000-0000-0000-000000000001',
    'principal_id', '20000000-0000-0000-0000-000000000001',
    'caller_id', '30000000-0000-0000-0000-000000000001',
    'backend_pid', pg_backend_pid(), 'transaction_id', pg_current_xact_id()::text,
    'database_oid', v_db_oid, 'deployment_id', 'probe-deployment-1',
    'issuer', 'urn:qembed:context-issuer:probe', 'audience', v_audience,
    'key_id', 'probe-key-1', 'issued_at', clock_timestamp(),
    'expires_at', clock_timestamp() + interval '30 seconds', 'nonce', gen_random_uuid()
  );
  INSERT INTO pg_temp.qsa003_expected VALUES (v_base_claims);
  v_payload := convert_to(v_base_claims::text, 'UTF8');
  v_signature := pgsodium.crypto_sign_detached(v_payload, v_material.secret_key);
  INSERT INTO qsa003_probe.probe_tokens VALUES ('valid', v_payload, v_signature);

  v_claims := jsonb_set(v_base_claims, '{backend_pid}', to_jsonb(pg_backend_pid() + 1), false);
  v_payload := convert_to(v_claims::text, 'UTF8');
  v_signature := pgsodium.crypto_sign_detached(v_payload, v_material.secret_key);
  INSERT INTO qsa003_probe.probe_tokens VALUES ('wrong_backend', v_payload, v_signature);

  v_claims := jsonb_set(v_base_claims, '{deployment_id}', to_jsonb('another-deployment'::text), false);
  v_claims := jsonb_set(v_claims, '{audience}',
    to_jsonb('urn:qembed:postgres:deployment:another:database:' || v_db_oid), false);
  v_payload := convert_to(v_claims::text, 'UTF8');
  v_signature := pgsodium.crypto_sign_detached(v_payload, v_material.secret_key);
  INSERT INTO qsa003_probe.probe_tokens VALUES ('wrong_deployment', v_payload, v_signature);

  v_claims := jsonb_set(v_base_claims, '{database_oid}', to_jsonb((v_db_oid::bigint + 1)::text), false);
  v_payload := convert_to(v_claims::text, 'UTF8');
  v_signature := pgsodium.crypto_sign_detached(v_payload, v_material.secret_key);
  INSERT INTO qsa003_probe.probe_tokens VALUES ('wrong_database', v_payload, v_signature);

  v_claims := jsonb_set(v_base_claims, '{issued_at}', to_jsonb(clock_timestamp() - interval '2 minutes'), false);
  v_claims := jsonb_set(v_claims, '{expires_at}', to_jsonb(clock_timestamp() - interval '1 minute'), false);
  v_payload := convert_to(v_claims::text, 'UTF8');
  v_signature := pgsodium.crypto_sign_detached(v_payload, v_material.secret_key);
  INSERT INTO qsa003_probe.probe_tokens VALUES ('expired', v_payload, v_signature);
END
$$;

SET ROLE qembed_runtime;
DO $$
DECLARE
  v_token record;
  v_actual jsonb;
  v_expected jsonb;
  v_tampered bytea;
BEGIN
  SELECT * INTO STRICT v_token FROM qsa003_probe.probe_tokens WHERE test_case = 'valid';
  SELECT claims INTO STRICT v_expected FROM pg_temp.qsa003_expected;
  PERFORM set_config('app.tenant_id', 'ffffffff-ffff-ffff-ffff-ffffffffffff', true);
  PERFORM set_config('app.principal_id', 'ffffffff-ffff-ffff-ffff-ffffffffffff', true);
  PERFORM set_config('app.caller_id', 'ffffffff-ffff-ffff-ffff-ffffffffffff', true);
  v_actual := qsa003_probe.verified_context(v_token.payload, v_token.signature);
  IF v_actual IS DISTINCT FROM v_expected THEN
    RAISE EXCEPTION 'valid token rejected or verified claims changed by forged legacy GUCs';
  END IF;
  v_tampered := set_byte(v_token.signature, octet_length(v_token.signature) - 1,
    get_byte(v_token.signature, octet_length(v_token.signature) - 1) # 1);
  IF qsa003_probe.verified_context(v_token.payload, v_tampered) IS NOT NULL THEN
    RAISE EXCEPTION 'modified signature was accepted';
  END IF;
  FOR v_token IN SELECT * FROM qsa003_probe.probe_tokens
    WHERE test_case IN ('wrong_backend', 'wrong_deployment', 'wrong_database', 'expired')
  LOOP
    IF qsa003_probe.verified_context(v_token.payload, v_token.signature) IS NOT NULL THEN
      RAISE EXCEPTION 'invalid token accepted: %', v_token.test_case;
    END IF;
  END LOOP;
  IF has_table_privilege(current_user, 'qsa003_probe.verification_keys', 'SELECT') THEN
    RAISE EXCEPTION 'runtime can read verification-key metadata';
  END IF;
  IF has_function_privilege(current_user, 'pgsodium.crypto_sign_detached(bytea, bytea)', 'EXECUTE') THEN
    RAISE EXCEPTION 'runtime can sign context tokens';
  END IF;
END
$$;
RESET ROLE;
COMMIT;

-- Same backend, different transaction: a committed token must fail.
BEGIN;
SET ROLE qembed_runtime;
DO $$
DECLARE v_token record;
BEGIN
  SELECT * INTO STRICT v_token FROM qsa003_probe.probe_tokens WHERE test_case = 'valid';
  IF qsa003_probe.verified_context(v_token.payload, v_token.signature) IS NOT NULL THEN
    RAISE EXCEPTION 'committed transaction token replayed in a later transaction';
  END IF;
END
$$;
RESET ROLE;
COMMIT;

-- Workflow checks backend binding through a second independent connection.
DO $$
DECLARE v_config text[];
BEGIN
  SELECT proconfig INTO STRICT v_config FROM pg_proc
    WHERE oid = 'qsa003_probe.verified_context(bytea,bytea)'::regprocedure;
  IF NOT (SELECT prosecdef FROM pg_proc
          WHERE oid = 'qsa003_probe.verified_context(bytea,bytea)'::regprocedure) THEN
    RAISE EXCEPTION 'verifier is not SECURITY DEFINER';
  END IF;
  IF array_to_string(v_config, ',') NOT LIKE '%search_path=pg_catalog, pgsodium, qsa003_probe, pg_temp' THEN
    RAISE EXCEPTION 'verifier search_path is not pinned with pg_temp last: %', v_config;
  END IF;
END
$$;
