-- Prototype only: proves build/API/ACL behavior, not RT-050 transaction binding.
CREATE EXTENSION pgsodium;

DO $$
DECLARE
  v_pair record;
  v_message bytea := convert_to('qembed RT-050 PostgreSQL 19 probe', 'UTF8');
  v_signature bytea;
BEGIN
  SELECT * INTO STRICT v_pair FROM pgsodium.crypto_sign_new_keypair();
  v_signature := pgsodium.crypto_sign_detached(v_message, v_pair.secret);

  IF NOT pgsodium.crypto_sign_verify_detached(v_signature, v_message, v_pair.public) THEN
    RAISE EXCEPTION 'Ed25519 verification rejected a valid signature';
  END IF;

  IF pgsodium.crypto_sign_verify_detached(
       v_signature, convert_to('tampered', 'UTF8'), v_pair.public
     ) THEN
    RAISE EXCEPTION 'Ed25519 verification accepted a modified message';
  END IF;
END
$$;

CREATE ROLE qembed_runtime NOLOGIN;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA pgsodium FROM PUBLIC;
GRANT USAGE ON SCHEMA pgsodium TO qembed_runtime;
GRANT EXECUTE ON FUNCTION pgsodium.crypto_sign_verify_detached(bytea, bytea, bytea)
  TO qembed_runtime;

CREATE TEMP TABLE qsa003_verify_probe (
  public_key bytea NOT NULL,
  message bytea NOT NULL,
  signature bytea NOT NULL
);

DO $$
DECLARE
  v_pair record;
  v_message bytea := convert_to('least privilege verification', 'UTF8');
BEGIN
  SELECT * INTO STRICT v_pair FROM pgsodium.crypto_sign_new_keypair();
  INSERT INTO qsa003_verify_probe(public_key, message, signature)
  VALUES (
    v_pair.public,
    v_message,
    pgsodium.crypto_sign_detached(v_message, v_pair.secret)
  );
END
$$;

GRANT SELECT ON qsa003_verify_probe TO qembed_runtime;
SET ROLE qembed_runtime;

DO $$
DECLARE
  v_probe record;
BEGIN
  SELECT * INTO STRICT v_probe FROM qsa003_verify_probe;
  IF NOT pgsodium.crypto_sign_verify_detached(
    v_probe.signature, v_probe.message, v_probe.public_key
  ) THEN
    RAISE EXCEPTION 'runtime role could not verify valid signature';
  END IF;

  IF has_function_privilege(
    current_user,
    'pgsodium.crypto_sign_detached(bytea, bytea)',
    'EXECUTE'
  ) THEN
    RAISE EXCEPTION 'runtime role unexpectedly has signing capability';
  END IF;

  IF has_function_privilege(
    current_user,
    'pgsodium.crypto_sign_new_keypair()',
    'EXECUTE'
  ) THEN
    RAISE EXCEPTION 'runtime role unexpectedly has key-generation capability';
  END IF;
END
$$;

RESET ROLE;
