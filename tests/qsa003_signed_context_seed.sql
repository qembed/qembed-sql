-- Deterministic rows for QSA-003 full-schema signed-context RLS assertions.
INSERT INTO tenants (id) VALUES
 ('10000000-0000-0000-0000-000000000001'),
 ('10000000-0000-0000-0000-000000000002');

INSERT INTO owner_principals (tenant_id, caller_id, principal_kind)
VALUES ('10000000-0000-0000-0000-000000000001',
        '20000000-0000-0000-0000-000000000001', 'tenant_owner');

INSERT INTO callers (id, tenant_id, token_hash, caller_kind)
VALUES
 ('30000000-0000-0000-0000-000000000001',
  '10000000-0000-0000-0000-000000000001', decode(repeat('a1', 32), 'hex'), 'Authenticated'),
 ('30000000-0000-0000-0000-000000000002',
  '10000000-0000-0000-0000-000000000001', decode(repeat('b2', 32), 'hex'), 'Authenticated');

INSERT INTO principal_caller_delegations
 (delegation_id, tenant_id, principal_id, caller_id)
VALUES
 ('60000000-0000-0000-0000-000000000001',
  '10000000-0000-0000-0000-000000000001',
  '20000000-0000-0000-0000-000000000001',
  '30000000-0000-0000-0000-000000000001');

INSERT INTO objects (tenant_id, object_id, state)
VALUES
 ('10000000-0000-0000-0000-000000000001',
  '40000000-0000-0000-0000-000000000001', 'draft'),
 ('10000000-0000-0000-0000-000000000002',
  '40000000-0000-0000-0000-000000000002', 'draft');

INSERT INTO object_versions
 (tenant_id, object_id, object_version_id, version_number, status, published_at)
VALUES
 ('10000000-0000-0000-0000-000000000001',
  '40000000-0000-0000-0000-000000000001',
  '70000000-0000-0000-0000-000000000001', 1, 'published', now());

UPDATE objects
   SET state = 'active',
       published_version_id = '70000000-0000-0000-0000-000000000001'
 WHERE tenant_id = '10000000-0000-0000-0000-000000000001'
   AND object_id = '40000000-0000-0000-0000-000000000001';

INSERT INTO memories
 (id, tenant_id, object_id, caller_id, memory_kind, claim, source_kind,
  verification, confidence, expires_at)
VALUES
 ('50000000-0000-0000-0000-000000000001',
  '10000000-0000-0000-0000-000000000001',
  '40000000-0000-0000-0000-000000000001',
  '30000000-0000-0000-0000-000000000001',
  'episodic', 'caller A episodic fixture', 'User', 'Unverified', 0.8, now() + interval '1 day'),
 ('50000000-0000-0000-0000-000000000002',
  '10000000-0000-0000-0000-000000000001',
  '40000000-0000-0000-0000-000000000001',
  '30000000-0000-0000-0000-000000000002',
  'episodic', 'caller B episodic fixture', 'User', 'Unverified', 0.8, now() + interval '1 day'),
 ('50000000-0000-0000-0000-000000000003',
  '10000000-0000-0000-0000-000000000001',
  '40000000-0000-0000-0000-000000000001',
  NULL,
  'semantic', 'tenant semantic fixture', 'User', 'Unverified', 0.8, NULL);
