-- PostgreSQL 19 feasibility probe for the minimal Qembed Ed25519 verifier.
-- Uses RFC 8032 test vector 1 (empty message) and test-only RLS fixtures.

DO $role$ BEGIN
  CREATE ROLE qembed_runtime NOLOGIN;
EXCEPTION WHEN duplicate_object THEN NULL;
END $role$;

CREATE SCHEMA qembed_crypto AUTHORIZATION postgres;
CREATE EXTENSION qembed_context_verify WITH SCHEMA qembed_crypto;

DO $crypto$
DECLARE
  v_signature bytea := decode(
    'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155' ||
    '5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b', 'hex');
  v_public_key bytea := decode(
    'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a', 'hex');
  v_tampered bytea;
BEGIN
  IF NOT qembed_crypto.qembed_context_verify_detached(v_signature, decode('', 'hex'), v_public_key) THEN
    RAISE EXCEPTION 'RFC 8032 valid signature was rejected';
  END IF;
  v_tampered := set_byte(v_signature, 0, get_byte(v_signature, 0) # 1);
  IF qembed_crypto.qembed_context_verify_detached(v_tampered, decode('', 'hex'), v_public_key) THEN
    RAISE EXCEPTION 'modified signature was accepted';
  END IF;
  IF qembed_crypto.qembed_context_verify_detached(v_signature, convert_to('x', 'UTF8'), v_public_key) THEN
    RAISE EXCEPTION 'signature for a different message was accepted';
  END IF;
  IF qembed_crypto.qembed_context_verify_detached(decode('00', 'hex'), decode('', 'hex'), v_public_key) THEN
    RAISE EXCEPTION 'invalid signature length was accepted';
  END IF;
  IF qembed_crypto.qembed_context_verify_detached(v_signature, decode('', 'hex'), decode('00', 'hex')) THEN
    RAISE EXCEPTION 'invalid public-key length was accepted';
  END IF;
END
$crypto$;

DO $catalog$
DECLARE v_preload text;
BEGIN
  SELECT current_setting('shared_preload_libraries') INTO v_preload;
  IF v_preload <> '' THEN
    RAISE EXCEPTION 'minimal verifier unexpectedly requires shared_preload_libraries: %', v_preload;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pgsodium') THEN
    RAISE EXCEPTION 'minimal verifier probe unexpectedly installed pgsodium';
  END IF;
  IF (SELECT count(*) FROM pg_proc p
      JOIN pg_depend d ON d.objid = p.oid AND d.deptype = 'e'
      JOIN pg_extension e ON e.oid = d.refobjid
      WHERE e.extname = 'qembed_context_verify') <> 1 THEN
    RAISE EXCEPTION 'extension must expose exactly one SQL function';
  END IF;
END
$catalog$;

REVOKE ALL ON SCHEMA qembed_crypto FROM PUBLIC;
GRANT USAGE ON SCHEMA qembed_crypto TO qembed_runtime;
GRANT EXECUTE ON FUNCTION qembed_crypto.qembed_context_verify_detached(bytea, bytea, bytea)
  TO postgres;

-- The test wrapper verifies a fixed RFC vector and returns its test tenant.
-- This isolates the C verifier cost in the RLS plan comparison.
CREATE FUNCTION qembed_crypto.context_tenant_id()
RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, qembed_crypto, pg_temp
AS $tenant$
  SELECT CASE WHEN qembed_crypto.qembed_context_verify_detached(
    decode(
      'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155' ||
      '5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b', 'hex'),
    decode('', 'hex'),
    decode('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a', 'hex')
  ) THEN '10000000-0000-0000-0000-000000000001'::uuid ELSE NULL END
$tenant$;
REVOKE ALL ON FUNCTION qembed_crypto.context_tenant_id() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION qembed_crypto.context_tenant_id() TO qembed_runtime;

CREATE TABLE qembed_crypto.tenant_rows_direct (tenant_id uuid NOT NULL, row_id bigint NOT NULL);
CREATE TABLE qembed_crypto.tenant_rows_initplan (tenant_id uuid NOT NULL, row_id bigint NOT NULL);
INSERT INTO qembed_crypto.tenant_rows_direct
SELECT CASE WHEN n <= 5000
  THEN '10000000-0000-0000-0000-000000000001'::uuid
  ELSE '10000000-0000-0000-0000-000000000002'::uuid END, n
FROM generate_series(1, 10000) AS g(n);
INSERT INTO qembed_crypto.tenant_rows_initplan SELECT * FROM qembed_crypto.tenant_rows_direct;
ALTER TABLE qembed_crypto.tenant_rows_direct ENABLE ROW LEVEL SECURITY;
ALTER TABLE qembed_crypto.tenant_rows_direct FORCE ROW LEVEL SECURITY;
ALTER TABLE qembed_crypto.tenant_rows_initplan ENABLE ROW LEVEL SECURITY;
ALTER TABLE qembed_crypto.tenant_rows_initplan FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows_direct_policy ON qembed_crypto.tenant_rows_direct
  USING (tenant_id = qembed_crypto.context_tenant_id());
CREATE POLICY tenant_rows_initplan_policy ON qembed_crypto.tenant_rows_initplan
  USING (tenant_id = (SELECT qembed_crypto.context_tenant_id()));
GRANT SELECT ON qembed_crypto.tenant_rows_direct, qembed_crypto.tenant_rows_initplan TO qembed_runtime;

SET ROLE qembed_runtime;
DO $rls$
DECLARE
  v_count bigint;
  v_plan json;
BEGIN
  IF has_function_privilege(current_user,
       'qembed_crypto.qembed_context_verify_detached(bytea,bytea,bytea)', 'EXECUTE') THEN
    RAISE EXCEPTION 'runtime role can invoke low-level verifier directly';
  END IF;
  IF has_schema_privilege(current_user, 'qembed_crypto', 'CREATE') THEN
    RAISE EXCEPTION 'runtime role can create objects in verifier schema';
  END IF;
  SELECT count(*) INTO v_count FROM qembed_crypto.tenant_rows_direct;
  IF v_count <> 5000 THEN
    RAISE EXCEPTION 'direct RLS policy returned %, expected 5000', v_count;
  END IF;
  SELECT count(*) INTO v_count FROM qembed_crypto.tenant_rows_initplan;
  IF v_count <> 5000 THEN
    RAISE EXCEPTION 'InitPlan RLS policy returned %, expected 5000', v_count;
  END IF;
  EXECUTE 'EXPLAIN (FORMAT JSON) SELECT count(*) FROM qembed_crypto.tenant_rows_initplan'
    INTO v_plan;
  IF v_plan::text NOT LIKE '%InitPlan%' THEN
    RAISE EXCEPTION 'uncorrelated RLS context subquery did not become an InitPlan: %', v_plan;
  END IF;
END
$rls$;
EXPLAIN (ANALYZE, BUFFERS, SUMMARY)
  SELECT count(*) FROM qembed_crypto.tenant_rows_direct;
EXPLAIN (ANALYZE, BUFFERS, SUMMARY)
  SELECT count(*) FROM qembed_crypto.tenant_rows_initplan;
RESET ROLE;

DROP SCHEMA qembed_crypto CASCADE;
DROP ROLE qembed_runtime;
