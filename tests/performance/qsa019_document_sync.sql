\set ON_ERROR_STOP on
SET client_min_messages=warning;
SET track_io_timing=on;

-- Keep the baseline phase representative even when the canonical schema
-- already contains the production candidate index.
DROP INDEX IF EXISTS idx_chunks_document;

-- Controlled PG19 benchmark for QSA-019.
-- 100 documents x 1,000 chunks under one tenant/object makes the current
-- (tenant_id, object_id, valid_from_revision, valid_to_revision) index unable
-- to narrow by document_id. Compare the same predicate and trigger workload
-- before/after the candidate child-side index.
INSERT INTO knowledge_documents
  (id, tenant_id, object_id, doc_key, title, status)
SELECT md5('qsa019-doc-' || n)::uuid,
       'aaaaaaaa-0000-0000-0000-000000000001',
       '0b000000-0000-0000-0000-000000000001',
       'qsa019-' || n,
       'QSA-019 benchmark document ' || n,
       'staged'
  FROM generate_series(1, 100) AS n;

INSERT INTO knowledge_chunks
  (id, tenant_id, object_id, document_id, content, position)
SELECT md5('qsa019-chunk-' || d || '-' || n)::uuid,
       'aaaaaaaa-0000-0000-0000-000000000001',
       '0b000000-0000-0000-0000-000000000001',
       md5('qsa019-doc-' || d)::uuid,
       'QSA-019 benchmark chunk ' || n,
       n
  FROM generate_series(1, 100) AS d
 CROSS JOIN generate_series(1, 1000) AS n;

ANALYZE knowledge_chunks;

\echo '=== QSA-019 BEFORE candidate index: document chunk lookup ==='
EXPLAIN (ANALYZE, BUFFERS, SETTINGS)
SELECT id
  FROM knowledge_chunks
 WHERE tenant_id = 'aaaaaaaa-0000-0000-0000-000000000001'
   AND object_id = '0b000000-0000-0000-0000-000000000001'
   AND document_id = md5('qsa019-doc-42')::uuid;

\echo '=== QSA-019 BEFORE candidate index: document interval synchronization ==='
EXPLAIN (ANALYZE, BUFFERS, SETTINGS)
UPDATE knowledge_documents
   SET status = 'live', valid_from_revision = 1
 WHERE id = md5('qsa019-doc-43')::uuid;

\echo '=== QSA-019 BEFORE candidate index: document delete cascade ==='
EXPLAIN (ANALYZE, BUFFERS, SETTINGS)
DELETE FROM knowledge_documents
 WHERE id = md5('qsa019-doc-44')::uuid;

CREATE INDEX qsa019_bench_chunks_document_idx
  ON knowledge_chunks (tenant_id, object_id, document_id);
ANALYZE knowledge_chunks;

SELECT pg_size_pretty(pg_relation_size('qsa019_bench_chunks_document_idx'))
  AS qsa019_candidate_index_size;

\echo '=== QSA-019 AFTER candidate index: document chunk lookup ==='
EXPLAIN (ANALYZE, BUFFERS, SETTINGS)
SELECT id
  FROM knowledge_chunks
 WHERE tenant_id = 'aaaaaaaa-0000-0000-0000-000000000001'
   AND object_id = '0b000000-0000-0000-0000-000000000001'
   AND document_id = md5('qsa019-doc-42')::uuid;

\echo '=== QSA-019 AFTER candidate index: document interval synchronization ==='
EXPLAIN (ANALYZE, BUFFERS, SETTINGS)
UPDATE knowledge_documents
   SET status = 'live', valid_from_revision = 1
 WHERE id = md5('qsa019-doc-45')::uuid;

\echo '=== QSA-019 AFTER candidate index: document delete cascade ==='
EXPLAIN (ANALYZE, BUFFERS, SETTINGS)
DELETE FROM knowledge_documents
 WHERE id = md5('qsa019-doc-46')::uuid;
