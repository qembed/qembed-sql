-- RUST-061: authoritative Caller deletion ledger.
--
-- Apply this migration to the dedicated Control-plane PostgreSQL database,
-- never to the Runtime database. The Control-plane cluster must have an
-- independent backup/PITR and recovery domain.
--
-- The application stores only a tenant-scoped HMAC digest. Raw Caller IDs,
-- credentials and Caller content must never be written to this database.

BEGIN;

DO $roles$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'qembed_control_plane_runtime') THEN
        CREATE ROLE qembed_control_plane_runtime
            NOLOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
    END IF;
END
$roles$;

ALTER ROLE qembed_control_plane_runtime
    NOLOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;

CREATE SCHEMA IF NOT EXISTS qembed_control_plane;
REVOKE ALL ON SCHEMA qembed_control_plane FROM PUBLIC;
GRANT USAGE ON SCHEMA qembed_control_plane TO qembed_control_plane_runtime;

CREATE TABLE qembed_control_plane.caller_deletion_tombstones (
    sequence_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id UUID NOT NULL,
    caller_hash BYTEA NOT NULL CHECK (octet_length(caller_hash) = 32),
    key_version TEXT NOT NULL CHECK (key_version = 'v1'),
    deleted_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (tenant_id, caller_hash)
);

COMMENT ON TABLE qembed_control_plane.caller_deletion_tombstones IS
    'Append-only authoritative Caller erasure tombstones; contains no raw Caller ID or Caller content.';
COMMENT ON COLUMN qembed_control_plane.caller_deletion_tombstones.caller_hash IS
    'HMAC-SHA-256(K_v1, domain || tenant UUID bytes || Caller UUID bytes).';
COMMENT ON COLUMN qembed_control_plane.caller_deletion_tombstones.sequence_id IS
    'Monotonic replay cursor. Writers and snapshot readers serialize through advisory transaction lock 61061.';

CREATE FUNCTION qembed_control_plane.reject_tombstone_row_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, qembed_control_plane
AS $reject_tombstone_row_mutation$
BEGIN
    RAISE EXCEPTION 'Caller deletion tombstones are append-only'
        USING ERRCODE = '55000';
END
$reject_tombstone_row_mutation$;

CREATE FUNCTION qembed_control_plane.reject_tombstone_truncate()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, qembed_control_plane
AS $reject_tombstone_truncate$
BEGIN
    RAISE EXCEPTION 'Caller deletion tombstones cannot be truncated'
        USING ERRCODE = '55000';
END
$reject_tombstone_truncate$;

CREATE TRIGGER caller_deletion_tombstones_no_update_delete
    BEFORE UPDATE OR DELETE ON qembed_control_plane.caller_deletion_tombstones
    FOR EACH ROW EXECUTE FUNCTION qembed_control_plane.reject_tombstone_row_mutation();

CREATE TRIGGER caller_deletion_tombstones_no_truncate
    BEFORE TRUNCATE ON qembed_control_plane.caller_deletion_tombstones
    FOR EACH STATEMENT EXECUTE FUNCTION qembed_control_plane.reject_tombstone_truncate();

REVOKE ALL ON TABLE qembed_control_plane.caller_deletion_tombstones FROM PUBLIC;
REVOKE ALL ON SEQUENCE qembed_control_plane.caller_deletion_tombstones_sequence_id_seq FROM PUBLIC;
GRANT SELECT, INSERT ON TABLE qembed_control_plane.caller_deletion_tombstones
    TO qembed_control_plane_runtime;
GRANT USAGE, SELECT ON SEQUENCE qembed_control_plane.caller_deletion_tombstones_sequence_id_seq
    TO qembed_control_plane_runtime;

REVOKE ALL ON FUNCTION qembed_control_plane.reject_tombstone_row_mutation() FROM PUBLIC;
REVOKE ALL ON FUNCTION qembed_control_plane.reject_tombstone_truncate() FROM PUBLIC;

COMMIT;
