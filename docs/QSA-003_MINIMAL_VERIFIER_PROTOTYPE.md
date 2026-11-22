# QSA-003 — minimal Ed25519 verifier prototype

**Status:** Alternative feasibility prototype only. No production DDL, no RLS migration, and no decision to replace pgsodium.

## Design

This prototype exposes one PostgreSQL C function:

`qembed_crypto.qembed_context_verify_detached(signature bytea, message bytea, public_key bytea) -> boolean`

It calls libsodium `crypto_sign_verify_detached`, accepts only 64-byte signatures and 32-byte public keys, and rejects messages larger than 8 KiB. It exposes no key-generation, signing, encryption, key-derivation, or event-trigger API. The function is immutable, strict, and parallel safe. The SQL extension revokes EXECUTE from PUBLIC; the test runtime role is not granted direct access to the low-level function.

The C module initializes libsodium when loaded by a backend. It does not require `shared_preload_libraries`, a pgsodium DDL event trigger, a getkey script, or a server root key.

## Test

The PostgreSQL 19 workflow builds the extension against the distribution's libsodium development package (Bookworm libsodium 1.0.18), then:

- verifies the RFC 8032 Ed25519 test vector;
- rejects a modified signature, modified message, invalid signature length, and invalid public-key length;
- confirms pgsodium is not installed and `shared_preload_libraries` remains empty;
- confirms the extension exposes exactly one SQL function;
- confirms the runtime role cannot call the low-level verifier directly or create objects in its schema;
- runs the same test-only RLS plan comparison: direct verifier call versus an uncorrelated scalar subquery expected to become an `InitPlan`.

The PostgreSQL 19 CI run #2 measured the direct C verifier policy at 7.377 ms and the `InitPlan` form at 0.480 ms on the same 10,000-row fixture (5,000 visible rows, no tenant index), approximately 15.4x. This is a microbenchmark, not a production guarantee. Unlike the pgsodium test, the minimal C function does not query a verification-key table or parse claims; the result isolates the primitive's per-row call overhead.

## Limitations

- This is new Qembed-maintained native C code and needs independent security review, fuzzing, ABI/build provenance, supported PostgreSQL matrix, and packaging/update policy.
- The RFC vector verifies the primitive only. The test does not yet integrate the full signed JSON claims, trusted public-key table, transaction binding, issuer, or Rust transaction API.
- The RLS wrapper uses a fixed test vector and tenant ID to isolate verifier evaluation cost; it is not a production context parser or policy.
- No cross-cluster replay, key rotation/revocation, Caller delegation race, issuer outage, retry, or pool lifecycle test is included.
- The prototype is in `qembed-sql` only for evaluation; if adopted, extension source/package ownership and release lifecycle must be decided explicitly.

Compare this branch with [the pgsodium prototype PR #68](https://github.com/qembed/qembed-sql/pull/68). Neither prototype is production-approved.

## Validation evidence

- [Minimal verifier workflow run #5](https://github.com/qembed/qembed-sql/actions/runs/45023293717) and [SQL smoke run #273](https://github.com/qembed/qembed-sql/actions/runs/45023293681) passed on the PostgreSQL 19 / pgvector 0.8.7 image using Debian Bookworm libsodium 1.0.18. The build emitted no compiler warnings in the captured job log.
