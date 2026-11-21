\set ON_ERROR_STOP on
SET client_min_messages=warning;
SET track_io_timing=on;

-- QSA-021 source revalidation: knowledge_chunks.id is globally PRIMARY KEY,
-- while knowledge_chunk_embeddings has PK (tenant_id, chunk_id, model_id).
-- Therefore (tenant_id, chunk_id) is already a selective prefix for the FK
-- lookup; object_id is an additional consistency predicate, not a cardinality
-- dimension. Measure the existing path at 100k rows before proposing an index.
INSERT INTO tenants(id)
VALUES ('a0210000-0000-0000-0000-000000000001');

INSERT INTO objects(tenant_id, object_id, state)
VALUES ('a0210000-0000-0000-0000-000000000001',
        'a0220000-0000-0000-0000-000000000001', 'draft');

INSERT INTO knowledge_documents
  (id, tenant_id, object_id, doc_key, title, status)
VALUES (md5('qsa021-document')::uuid,
        'a0210000-0000-0000-0000-000000000001',
        'a0220000-0000-0000-0000-000000000001',
        'qsa021-document', 'QSA-021 benchmark document', 'staged');

INSERT INTO knowledge_chunks
  (id, tenant_id, object_id, document_id, content, position)
SELECT md5('qsa021-chunk-' || n)::uuid,
       'a0210000-0000-0000-0000-000000000001',
       'a0220000-0000-0000-0000-000000000001',
       md5('qsa021-document')::uuid,
       'QSA-021 benchmark chunk ' || n,
       n
  FROM generate_series(1, 100000) AS n;

INSERT INTO knowledge_chunk_embeddings
  (tenant_id, object_id, chunk_id, model_id, embedding)
SELECT 'a0210000-0000-0000-0000-000000000001',
       'a0220000-0000-0000-0000-000000000001',
       md5('qsa021-chunk-' || n)::uuid,
       'm3', '[1,0,0]'
  FROM generate_series(1, 100000) AS n;

ANALYZE knowledge_chunk_embeddings;

\echo '=== QSA-021 existing PK-prefix lookup ==='
EXPLAIN (ANALYZE, BUFFERS, SETTINGS)
SELECT chunk_id
  FROM knowledge_chunk_embeddings
 WHERE tenant_id = 'a0210000-0000-0000-0000-000000000001'
   AND object_id = 'a0220000-0000-0000-0000-000000000001'
   AND chunk_id = md5('qsa021-chunk-42000')::uuid;

\echo '=== QSA-021 delete one chunk and cascade to its embedding ==='
EXPLAIN (ANALYZE, BUFFERS, SETTINGS)
DELETE FROM knowledge_chunks
 WHERE id = md5('qsa021-chunk-43000')::uuid;

\echo '=== QSA-021 existing PK size ==='
SELECT pg_size_pretty(pg_relation_size('knowledge_chunk_embeddings_pkey'))
  AS existing_pk_size;
