-- RUST-061a: serialize sequence assignment with every tombstone writer.
--
-- Identity/default sequence values are allocated before BEFORE INSERT triggers.
-- Replace the identity with a trigger-assigned sequence so the advisory lock is
-- acquired BEFORE a sequence value exists. This makes the replay high-water mark
-- safe even if a future writer omits the Rust-side lock call.

BEGIN;

ALTER TABLE qembed_control_plane.caller_deletion_tombstones
    ALTER COLUMN sequence_id DROP IDENTITY IF EXISTS;
ALTER TABLE qembed_control_plane.caller_deletion_tombstones
    ALTER COLUMN sequence_id DROP DEFAULT;

CREATE SEQUENCE IF NOT EXISTS qembed_control_plane.caller_deletion_tombstones_order_seq
    AS BIGINT
    INCREMENT BY 1
    MINVALUE 1
    NO MAXVALUE
    START WITH 1
    NO CYCLE;

SELECT setval(
    'qembed_control_plane.caller_deletion_tombstones_order_seq',
    COALESCE(
        (SELECT MAX(sequence_id) + 1
           FROM qembed_control_plane.caller_deletion_tombstones),
        1
    ),
    false
);

ALTER SEQUENCE qembed_control_plane.caller_deletion_tombstones_order_seq
    OWNED BY qembed_control_plane.caller_deletion_tombstones.sequence_id;

CREATE FUNCTION qembed_control_plane.assign_tombstone_sequence()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, qembed_control_plane
AS $assign_tombstone_sequence$
BEGIN
    IF NEW.sequence_id IS NOT NULL THEN
        RAISE EXCEPTION 'Caller deletion sequence is assigned by the ledger'
            USING ERRCODE = '42501';
    END IF;

    PERFORM pg_advisory_xact_lock(61061);
    NEW.sequence_id := nextval(
        'qembed_control_plane.caller_deletion_tombstones_order_seq'::regclass
    );
    RETURN NEW;
END
$assign_tombstone_sequence$;

CREATE TRIGGER caller_deletion_tombstones_assign_sequence
    BEFORE INSERT ON qembed_control_plane.caller_deletion_tombstones
    FOR EACH ROW EXECUTE FUNCTION qembed_control_plane.assign_tombstone_sequence();

REVOKE ALL ON SEQUENCE qembed_control_plane.caller_deletion_tombstones_order_seq FROM PUBLIC;
GRANT USAGE, SELECT ON SEQUENCE qembed_control_plane.caller_deletion_tombstones_order_seq
    TO qembed_control_plane_runtime;
REVOKE ALL ON FUNCTION qembed_control_plane.assign_tombstone_sequence() FROM PUBLIC;

COMMIT;
