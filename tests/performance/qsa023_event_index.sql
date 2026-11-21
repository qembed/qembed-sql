\set ON_ERROR_STOP on
SET client_min_messages=warning;
SET track_io_timing=on;

-- QSA-023: events_aggregate_order_idx duplicates the unique index created by
-- events_stream_version_unique. Recreate an equivalent temporary duplicate so
-- this benchmark remains valid after the canonical schema removes the extra index.
DROP INDEX IF EXISTS events_aggregate_order_idx;
DROP INDEX IF EXISTS qsa023_bench_duplicate_idx;

INSERT INTO events
  (tenant_id, event_id, aggregate_type, aggregate_id, stream_version, event_type, payload)
SELECT 'aaaaaaaa-0000-0000-0000-000000000001',
       md5('qsa023-event-' || n)::uuid,
       'qsa023-benchmark',
       md5('qsa023-aggregate-' || ((n - 1) / 1000 + 1))::uuid,
       NULL,
       'QSA023BenchmarkEvent',
       '{}'::jsonb
  FROM generate_series(1, 100000) AS n;

ANALYZE events;

CREATE INDEX qsa023_bench_duplicate_idx
  ON events (tenant_id, aggregate_type, aggregate_id, stream_version);
ANALYZE events;

\echo '=== QSA-023 BEFORE dropping duplicate: aggregate event order lookup ==='
EXPLAIN (ANALYZE, BUFFERS, SETTINGS)
SELECT event_id, stream_version
  FROM events
 WHERE tenant_id = 'aaaaaaaa-0000-0000-0000-000000000001'
   AND aggregate_type = 'qsa023-benchmark'
   AND aggregate_id = md5('qsa023-aggregate-42')::uuid
 ORDER BY stream_version DESC
 LIMIT 100;

SELECT pg_size_pretty(pg_relation_size('qsa023_bench_duplicate_idx'))
         AS duplicate_index_size,
       pg_size_pretty(pg_relation_size('events_stream_version_unique'))
         AS unique_index_size;

DROP INDEX qsa023_bench_duplicate_idx;
ANALYZE events;

\echo '=== QSA-023 AFTER dropping duplicate: aggregate event order lookup ==='
EXPLAIN (ANALYZE, BUFFERS, SETTINGS)
SELECT event_id, stream_version
  FROM events
 WHERE tenant_id = 'aaaaaaaa-0000-0000-0000-000000000001'
   AND aggregate_type = 'qsa023-benchmark'
   AND aggregate_id = md5('qsa023-aggregate-42')::uuid
 ORDER BY stream_version DESC
 LIMIT 100;

\echo '=== QSA-023 unique index definition retained ==='
SELECT pg_get_indexdef('events_stream_version_unique'::regclass);
