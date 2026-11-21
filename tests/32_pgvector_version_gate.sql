-- QSA-011: pgvector must be at least 0.8.7, including the patch component.
\set ON_ERROR_STOP on
SET client_min_messages=warning;

SELECT tt.chk('QSA-011 rejects pgvector versions below 0.8.7 and compares patch numerically',
  $q$SELECT NOT qembed_pgvector_version_supported('0.8.0')
       AND NOT qembed_pgvector_version_supported('0.8.6')
       AND qembed_pgvector_version_supported('0.8.7')
       AND qembed_pgvector_version_supported('0.8.10')
       AND qembed_pgvector_version_supported('0.9.0')
       AND qembed_pgvector_version_supported('1.0.0')
       AND NOT qembed_pgvector_version_supported('0.8')$q$);

SELECT tt.chk('QSA-011 installed vector extension satisfies the enforced minimum',
  $q$SELECT qembed_pgvector_version_supported(extversion)
       FROM pg_extension WHERE extname='vector'$q$);
