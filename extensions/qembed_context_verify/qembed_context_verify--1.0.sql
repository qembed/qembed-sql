CREATE FUNCTION qembed_context_verify_detached(
  signature bytea,
  message bytea,
  public_key bytea
)
RETURNS boolean
AS 'MODULE_PATHNAME', 'qembed_context_verify_detached'
LANGUAGE C IMMUTABLE STRICT PARALLEL SAFE;

REVOKE ALL ON FUNCTION qembed_context_verify_detached(bytea, bytea, bytea)
  FROM PUBLIC;
