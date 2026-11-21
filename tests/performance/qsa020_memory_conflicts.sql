\set ON_ERROR_STOP on
SET client_min_messages=warning;
SET track_io_timing=on;

-- Controlled PG19 benchmark for QSA-020.
-- 100 memories, each with 1,000 outgoing and 1,000 incoming conflict edges.
-- This isolates both memory_conflicts FK cascades. memory_embeddings already
-- has a PK prefix (tenant_id, memory_id), and memory.id is globally unique;
-- measure that access path rather than adding a duplicate index speculatively.
INSERT INTO tenants(id)
VALUES ('a0200000-0000-0000-0000-000000000001');

INSERT INTO objects(tenant_id, object_id, state)
VALUES ('a0200000-0000-0000-0000-000000000001',
        'a0210000-0000-0000-0000-000000000001', 'draft');

INSERT INTO memories
  (id, tenant_id, object_id, memory_kind, claim, source_kind, verification, confidence)
SELECT md5('qsa020-memory-' || n)::uuid,
       'a0200000-0000-0000-0000-000000000001',
       'a0210000-0000-0000-0000-000000000001',
       'semantic', 'QSA-020 benchmark memory ' || n,
       'User', 'Unverified', 0.5
  FROM generate_series(1, 100) AS n;

INSERT INTO memory_embeddings
  (tenant_id, object_id, memory_id, model_id, embedding)
SELECT 'a0200000-0000-0000-0000-000000000001',
       'a0210000-0000-0000-0000-000000000001',
       md5('qsa020-memory-' || n)::uuid,
       'm3', '[1,0,0]'
  FROM generate_series(1, 100) AS n;

INSERT INTO memory_conflicts
  (id, tenant_id, object_id, memory_id, conflicting_memory_id, status)
SELECT md5('qsa020-conflict-' || d || '-' || n)::uuid,
       'a0200000-0000-0000-0000-000000000001',
       'a0210000-0000-0000-0000-000000000001',
       md5('qsa020-memory-' || d)::uuid,
       md5('qsa020-memory-' || (d % 100 + 1))::uuid,
       'open'
  FROM generate_series(1, 100) AS d
 CROSS JOIN generate_series(1, 1000) AS n;

ANALYZE memory_conflicts;
ANALYZE memory_embeddings;

\echo '=== QSA-020 CURRENT memory_embeddings PK-prefix lookup ==='
EXPLAIN (ANALYZE, BUFFERS, SETTINGS)
SELECT memory_id
  FROM memory_embeddings
 WHERE tenant_id = 'a0200000-0000-0000-0000-000000000001'
   AND object_id = 'a0210000-0000-0000-0000-000000000001'
   AND memory_id = md5('qsa020-memory-42')::uuid;

\echo '=== QSA-020 BEFORE indexes: memory_id conflict lookup ==='
EXPLAIN (ANALYZE, BUFFERS, SETTINGS)
SELECT id
  FROM memory_conflicts
 WHERE tenant_id = 'a0200000-0000-0000-0000-000000000001'
   AND object_id = 'a0210000-0000-0000-0000-000000000001'
   AND memory_id = md5('qsa020-memory-42')::uuid;

\echo '=== QSA-020 BEFORE indexes: conflicting_memory_id lookup ==='
EXPLAIN (ANALYZE, BUFFERS, SETTINGS)
SELECT id
  FROM memory_conflicts
 WHERE tenant_id = 'a0200000-0000-0000-0000-000000000001'
   AND object_id = 'a0210000-0000-0000-0000-000000000001'
   AND conflicting_memory_id = md5('qsa020-memory-42')::uuid;

\echo '=== QSA-020 BEFORE indexes: memory deletion and all FK cascades ==='
EXPLAIN (ANALYZE, BUFFERS, SETTINGS)
DELETE FROM memories
 WHERE id = md5('qsa020-memory-42')::uuid;

CREATE INDEX qsa020_bench_conflict_memory_idx
  ON memory_conflicts (tenant_id, object_id, memory_id);
CREATE INDEX qsa020_bench_conflicting_memory_idx
  ON memory_conflicts (tenant_id, object_id, conflicting_memory_id);
ANALYZE memory_conflicts;

SELECT pg_size_pretty(pg_relation_size('qsa020_bench_conflict_memory_idx'))
         AS memory_id_index_size,
       pg_size_pretty(pg_relation_size('qsa020_bench_conflicting_memory_idx'))
         AS conflicting_memory_id_index_size;

\echo '=== QSA-020 AFTER indexes: memory_id conflict lookup ==='
EXPLAIN (ANALYZE, BUFFERS, SETTINGS)
SELECT id
  FROM memory_conflicts
 WHERE tenant_id = 'a0200000-0000-0000-0000-000000000001'
   AND object_id = 'a0210000-0000-0000-0000-000000000001'
   AND memory_id = md5('qsa020-memory-43')::uuid;

\echo '=== QSA-020 AFTER indexes: conflicting_memory_id lookup ==='
EXPLAIN (ANALYZE, BUFFERS, SETTINGS)
SELECT id
  FROM memory_conflicts
 WHERE tenant_id = 'a0200000-0000-0000-0000-000000000001'
   AND object_id = 'a0210000-0000-0000-0000-000000000001'
   AND conflicting_memory_id = md5('qsa020-memory-43')::uuid;

\echo '=== QSA-020 AFTER indexes: memory deletion and all FK cascades ==='
EXPLAIN (ANALYZE, BUFFERS, SETTINGS)
DELETE FROM memories
 WHERE id = md5('qsa020-memory-43')::uuid;
