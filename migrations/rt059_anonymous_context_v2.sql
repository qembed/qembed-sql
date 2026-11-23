-- RT-059: versioned signed context for Anonymous public invocation.
-- qctx1 remains byte-for-byte compatible; qctx2 has a separate exact claim set.
BEGIN;

DO $preflight$
BEGIN
    IF to_regprocedure('qembed_crypto.verified_context(text)') IS NULL
       OR to_regclass('qembed_crypto.verification_keys') IS NULL
       OR NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'qembed_key_registry_owner')
       OR NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'qembed_runtime') THEN
        RAISE EXCEPTION 'RT-059 requires the RT-050 signed-context verifier and roles';
    END IF;
END
$preflight$;

CREATE OR REPLACE FUNCTION qembed_crypto.verified_context(p_token text)
RETURNS jsonb
LANGUAGE plpgsql STABLE
SECURITY DEFINER
SET search_path = pg_catalog, qembed_crypto, pg_temp
AS $verify$
DECLARE
  v_envelope_version text;
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
  IF p_token IS NULL OR length(p_token) > 16526
     OR p_token !~ '^qctx[12]:[0-9a-f]+:[0-9a-f]{128}$' THEN
    RETURN NULL;
  END IF;
  v_envelope_version := substring(p_token FROM 5 FOR 1);

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

  -- Only after signature verification do we treat parsed claims as trusted.
  v_claims := convert_from(v_payload, 'UTF8')::jsonb;
  IF jsonb_typeof(v_claims) <> 'object' THEN
    RETURN NULL;
  END IF;
  SELECT count(*) INTO v_claim_count FROM jsonb_object_keys(v_claims);

  IF v_envelope_version = '1' THEN
    IF v_claim_count <> 14 THEN
      RETURN NULL;
    END IF;
    FOREACH v_required_claim IN ARRAY ARRAY[
      'version', 'tenant_id', 'principal_id', 'backend_pid',
      'transaction_id', 'database_oid', 'deployment_id', 'issuer', 'audience',
      'key_id', 'issued_at', 'expires_at', 'nonce'
    ] LOOP
      IF jsonb_typeof(v_claims->v_required_claim) <> 'string' THEN
        RETURN NULL;
      END IF;
    END LOOP;
    IF NOT (v_claims ? 'caller_id')
       OR jsonb_typeof(v_claims->'caller_id') NOT IN ('string', 'null')
       OR v_claims->>'version' <> '1'
       OR v_claims->>'tenant_id' !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
       OR v_claims->>'principal_id' !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
       OR (jsonb_typeof(v_claims->'caller_id') = 'string'
           AND v_claims->>'caller_id' !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') THEN
      RETURN NULL;
    END IF;
  ELSIF v_envelope_version = '2' THEN
    IF v_claim_count <> 17 THEN
      RETURN NULL;
    END IF;
    FOREACH v_required_claim IN ARRAY ARRAY[
      'version', 'tenant_id', 'subject_kind', 'object_id',
      'subject_fingerprint', 'backend_pid', 'transaction_id', 'database_oid',
      'deployment_id', 'issuer', 'audience', 'key_id', 'issued_at',
      'expires_at', 'nonce'
    ] LOOP
      IF jsonb_typeof(v_claims->v_required_claim) <> 'string' THEN
        RETURN NULL;
      END IF;
    END LOOP;
    IF NOT (v_claims ? 'principal_id')
       OR jsonb_typeof(v_claims->'principal_id') <> 'null'
       OR NOT (v_claims ? 'caller_id')
       OR jsonb_typeof(v_claims->'caller_id') NOT IN ('string', 'null')
       OR v_claims->>'version' <> '2'
       OR v_claims->>'subject_kind' <> 'anonymous'
       OR v_claims->>'tenant_id' !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
       OR v_claims->>'object_id' !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
       OR v_claims->>'subject_fingerprint' !~ '^[0-9a-f]{64}$'
       OR (jsonb_typeof(v_claims->'caller_id') = 'string'
           AND v_claims->>'caller_id' !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') THEN
      RETURN NULL;
    END IF;
  ELSE
    RETURN NULL;
  END IF;

  IF v_claims->>'nonce' !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
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
  RETURN NULL;
END
$verify$;

CREATE OR REPLACE FUNCTION qembed_crypto.current_subject_kind()
RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, qembed_crypto, pg_temp
AS $subject$
  SELECT qembed_crypto.verified_context(
    current_setting('app.context_token', true)
  )->>'subject_kind'
$subject$;

CREATE OR REPLACE FUNCTION qembed_crypto.current_object_id()
RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, qembed_crypto, pg_temp
AS $object$
  SELECT (qembed_crypto.verified_context(
    current_setting('app.context_token', true)
  )->>'object_id')::uuid
$object$;

CREATE OR REPLACE FUNCTION qembed_crypto.current_anonymous_fingerprint()
RETURNS bytea
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, qembed_crypto, pg_temp
AS $fingerprint$
  SELECT decode(qembed_crypto.verified_context(
    current_setting('app.context_token', true)
  )->>'subject_fingerprint', 'hex')
$fingerprint$;

ALTER FUNCTION qembed_crypto.verified_context(text) OWNER TO qembed_key_registry_owner;
ALTER FUNCTION qembed_crypto.current_subject_kind() OWNER TO qembed_key_registry_owner;
ALTER FUNCTION qembed_crypto.current_object_id() OWNER TO qembed_key_registry_owner;
ALTER FUNCTION qembed_crypto.current_anonymous_fingerprint() OWNER TO qembed_key_registry_owner;

REVOKE ALL ON FUNCTION qembed_crypto.verified_context(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION qembed_crypto.current_subject_kind() FROM PUBLIC;
REVOKE ALL ON FUNCTION qembed_crypto.current_object_id() FROM PUBLIC;
REVOKE ALL ON FUNCTION qembed_crypto.current_anonymous_fingerprint() FROM PUBLIC;

GRANT EXECUTE ON FUNCTION qembed_crypto.current_subject_kind() TO qembed_runtime;
GRANT EXECUTE ON FUNCTION qembed_crypto.current_object_id() TO qembed_runtime;
GRANT EXECUTE ON FUNCTION qembed_crypto.current_anonymous_fingerprint() TO qembed_runtime;

DO $definer_grants$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'qembed_definer') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION qembed_crypto.current_subject_kind() TO qembed_definer';
        EXECUTE 'GRANT EXECUTE ON FUNCTION qembed_crypto.current_object_id() TO qembed_definer';
        EXECUTE 'GRANT EXECUTE ON FUNCTION qembed_crypto.current_anonymous_fingerprint() TO qembed_definer';
    END IF;
END
$definer_grants$;

COMMIT;
