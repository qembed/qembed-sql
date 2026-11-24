-- RUST-061: restore replay must revoke Callers, cancel in-flight work, and erase
-- caller-derived content without giving the restore role direct table access.
set ON_ERROR_STOP on

BEGIN;

INSERT INTO tenants (id) VALUES
    ('61000000-0000-4000-8000-000000000001');

INSERT INTO callers (id, tenant_id, token_hash, caller_kind) VALUES
    ('61000000-0000-4000-8000-000000000011',
     '61000000-0000-4000-8000-000000000001', digest('rt061-caller-a', 'sha256'), 'Authenticated'),
    ('61000000-0000-4000-8000-000000000012',
     '61000000-0000-4000-8000-000000000001', digest('rt061-caller-b', 'sha256'), 'Authenticated');

INSERT INTO objects (tenant_id, object_id, state) VALUES
    ('61000000-0000-4000-8000-000000000001',
     '61000000-0000-4000-8000-000000000021', 'draft');

INSERT INTO object_versions (
    tenant_id, object_id, object_version_id, version_number, status
) VALUES (
    '61000000-0000-4000-8000-000000000001',
    '61000000-0000-4000-8000-000000000021',
    '61000000-0000-4000-8000-000000000031', 1, 'draft'
);

INSERT INTO snapshots (
    tenant_id, snapshot_id, object_id, object_version_id, schema_version,
    canonical_json, content_hash, json_projection
) VALUES (
    '61000000-0000-4000-8000-000000000001',
    '61000000-0000-4000-8000-000000000041',
    '61000000-0000-4000-8000-000000000021',
    '61000000-0000-4000-8000-000000000031',
    1, convert_to('{}', 'UTF8'), digest(convert_to('{}', 'UTF8'), 'sha256'), '{}'::jsonb
);

INSERT INTO object_invocations (
    id, tenant_id, object_id, caller_id, snapshot_id, knowledge_revision,
    pool, status, trace_id
) VALUES
    ('61000000-0000-4000-8000-000000000051',
     '61000000-0000-4000-8000-000000000001',
     '61000000-0000-4000-8000-000000000021',
     '61000000-0000-4000-8000-000000000011',
     '61000000-0000-4000-8000-000000000041', 0, 'authenticated', 'Received',
     '61000000-0000-4000-8000-000000000061'),
    ('61000000-0000-4000-8000-000000000052',
     '61000000-0000-4000-8000-000000000001',
     '61000000-0000-4000-8000-000000000021',
     '61000000-0000-4000-8000-000000000012',
     '61000000-0000-4000-8000-000000000041', 0, 'authenticated', 'Received',
     '61000000-0000-4000-8000-000000000062');

-- Caller A has completed work. Caller B still has an active invocation and
-- must remain pending until the cancellation is observed and reaches terminal.
UPDATE object_invocations
   SET status = 'Failed', error_code = 'test_terminal', finished_at = clock_timestamp(), version = 1
 WHERE id = '61000000-0000-4000-8000-000000000051';

INSERT INTO interaction_messages (
    id, tenant_id, object_id, caller_id, invocation_id, role, content, expires_at
) VALUES
    ('61000000-0000-4000-8000-000000000071',
     '61000000-0000-4000-8000-000000000001',
     '61000000-0000-4000-8000-000000000021',
     '61000000-0000-4000-8000-000000000011',
     '61000000-0000-4000-8000-000000000051', 'user', 'private caller A message',
     clock_timestamp() + interval '1 day'),
    ('61000000-0000-4000-8000-000000000072',
     '61000000-0000-4000-8000-000000000001',
     '61000000-0000-4000-8000-000000000021',
     '61000000-0000-4000-8000-000000000012',
     '61000000-0000-4000-8000-000000000052', 'user', 'private caller B message',
     clock_timestamp() + interval '1 day');

INSERT INTO invocation_idempotency (
    tenant_id, object_id, caller_id, idempotency_key, payload_hash, invocation_id, expires_at
) VALUES
    ('61000000-0000-4000-8000-000000000001',
     '61000000-0000-4000-8000-000000000021',
     '61000000-0000-4000-8000-000000000011', 'rt061-a', digest('a', 'sha256'),
     '61000000-0000-4000-8000-000000000051', clock_timestamp() + interval '1 day'),
    ('61000000-0000-4000-8000-000000000001',
     '61000000-0000-4000-8000-000000000021',
     '61000000-0000-4000-8000-000000000012', 'rt061-b', digest('b', 'sha256'),
     '61000000-0000-4000-8000-000000000052', clock_timestamp() + interval '1 day');

INSERT INTO memories (
    id, tenant_id, object_id, caller_id, memory_kind, claim, source_kind,
    verification, confidence, invocation_id, expires_at
) VALUES
    ('61000000-0000-4000-8000-000000000081',
     '61000000-0000-4000-8000-000000000001',
     '61000000-0000-4000-8000-000000000021',
     '61000000-0000-4000-8000-000000000011', 'episodic', 'private memory A',
     'User', 'Unverified', 0.9, '61000000-0000-4000-8000-000000000051',
     clock_timestamp() + interval '1 day'),
    ('61000000-0000-4000-8000-000000000082',
     '61000000-0000-4000-8000-000000000001',
     '61000000-0000-4000-8000-000000000021',
     '61000000-0000-4000-8000-000000000012', 'episodic', 'private memory B',
     'User', 'Unverified', 0.9, '61000000-0000-4000-8000-000000000052',
     clock_timestamp() + interval '1 day');

-- Restore role has only EXECUTE on the narrow replay function. It cannot read
-- Caller rows or any caller-derived table directly.
SET ROLE qembed_restore;
SELECT qembed_crypto.replay_caller_deletion(
    '61000000-0000-4000-8000-000000000001',
    public.hmac(
        convert_to('qembed/caller-deletion/v1', 'UTF8') || decode('00', 'hex')
        || pg_catalog.uuid_send('61000000-0000-4000-8000-000000000001'::uuid)
        || pg_catalog.uuid_send('61000000-0000-4000-8000-000000000011'::uuid),
        decode(repeat('a1', 32), 'hex'),
        'sha256'
    ),
    'v1',
    decode(repeat('a1', 32), 'hex')
);
SELECT qembed_crypto.replay_caller_deletion(
    '61000000-0000-4000-8000-000000000001',
    public.hmac(
        convert_to('qembed/caller-deletion/v1', 'UTF8') || decode('00', 'hex')
        || pg_catalog.uuid_send('61000000-0000-4000-8000-000000000001'::uuid)
        || pg_catalog.uuid_send('61000000-0000-4000-8000-000000000012'::uuid),
        decode(repeat('a1', 32), 'hex'),
        'sha256'
    ),
    'v1',
    decode(repeat('a1', 32), 'hex')
);
RESET ROLE;

DO $assert_rt061$
BEGIN
    IF (SELECT revoked_at IS NULL FROM callers
         WHERE id = '61000000-0000-4000-8000-000000000011') THEN
        RAISE EXCEPTION 'Caller A was not revoked';
    END IF;
    IF EXISTS (SELECT 1 FROM interaction_messages
                WHERE caller_id = '61000000-0000-4000-8000-000000000011')
       OR EXISTS (SELECT 1 FROM memories
                   WHERE caller_id = '61000000-0000-4000-8000-000000000011')
       OR EXISTS (SELECT 1 FROM invocation_idempotency
                   WHERE caller_id = '61000000-0000-4000-8000-000000000011') THEN
        RAISE EXCEPTION 'Caller A derived data was not erased';
    END IF;

    IF (SELECT revoked_at IS NULL FROM callers
         WHERE id = '61000000-0000-4000-8000-000000000012') THEN
        RAISE EXCEPTION 'Caller B was not revoked';
    END IF;
    IF (SELECT cancel_requested_at IS NULL FROM object_invocations
         WHERE id = '61000000-0000-4000-8000-000000000052') THEN
        RAISE EXCEPTION 'Caller B active invocation was not cancellation-requested';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM interaction_messages
                    WHERE caller_id = '61000000-0000-4000-8000-000000000012') THEN
        RAISE EXCEPTION 'Caller B data was erased before active work became terminal';
    END IF;
END
$assert_rt061$;

-- Once the worker has observed cancellation and persisted a terminal state,
-- replay becomes complete and the remaining derived data is erased.
UPDATE object_invocations
   SET status = 'Cancelled', finished_at = clock_timestamp(), version = version + 1
 WHERE id = '61000000-0000-4000-8000-000000000052';

SET ROLE qembed_restore;
SELECT qembed_crypto.replay_caller_deletion(
    '61000000-0000-4000-8000-000000000001',
    public.hmac(
        convert_to('qembed/caller-deletion/v1', 'UTF8') || decode('00', 'hex')
        || pg_catalog.uuid_send('61000000-0000-4000-8000-000000000001'::uuid)
        || pg_catalog.uuid_send('61000000-0000-4000-8000-000000000012'::uuid),
        decode(repeat('a1', 32), 'hex'),
        'sha256'
    ),
    'v1',
    decode(repeat('a1', 32), 'hex')
);
RESET ROLE;

DO $assert_rt061_complete$
BEGIN
    IF EXISTS (SELECT 1 FROM interaction_messages
                WHERE caller_id = '61000000-0000-4000-8000-000000000012')
       OR EXISTS (SELECT 1 FROM memories
                   WHERE caller_id = '61000000-0000-4000-8000-000000000012')
       OR EXISTS (SELECT 1 FROM invocation_idempotency
                   WHERE caller_id = '61000000-0000-4000-8000-000000000012') THEN
        RAISE EXCEPTION 'Caller B derived data remains after terminal replay';
    END IF;
END
$assert_rt061_complete$;

ROLLBACK;
