# QSA-003 — minimal Ed25519 verifier prototype

**Status:** Alternative feasibility prototype only. No production DDL, no production RLS migration, and no decision to replace pgsodium.

## Design

This prototype exposes one PostgreSQL C function:

`qembed_crypto.qembed_context_verify_detached(signature bytea, message bytea, public_key bytea) -> boolean`

It calls libsodium `crypto_sign_verify_detached`, accepts only 64-byte signatures and 32-byte public keys, and rejects messages larger than 8 KiB. It exposes no key-generation, signing, encryption, key-derivation, or event-trigger API. The function is immutable, strict, and parallel safe. The SQL extension revokes EXECUTE from PUBLIC; the runtime role is not granted direct access to the low-level function.

The C module initializes libsodium when loaded by a backend. It does not require `shared_preload_libraries`, pgsodium, a DDL event trigger, a getkey script, or a server root key.

## PostgreSQL 19 test coverage

The workflow builds against Debian Bookworm libsodium 1.0.18 and PostgreSQL 19, then performs two probes.

### Primitive and RLS plan probe

- verifies the RFC 8032 Ed25519 test vector;
- rejects a modified signature, modified message, invalid signature length, invalid public-key length, and payloads larger than 8 KiB;
- confirms pgsodium is not installed and `shared_preload_libraries` remains empty;
- confirms the extension exposes exactly one SQL function;
- confirms the runtime role cannot call the low-level verifier directly or create objects in the extension schema;
- compares direct verifier evaluation with an uncorrelated scalar subquery planned as an `InitPlan`.

In run #12, the 10,000-row primitive fixture measured 7.325 ms for direct C verification versus 0.686 ms through the `InitPlan` form (5,000 visible rows, no tenant index). This is a CI microbenchmark, not a production performance guarantee; timing varies with runner load.

### Full transaction-bound context probe

A separate Python test issuer uses ctypes/lib­sodium outside PostgreSQL to generate an Ed25519 keypair and sign the exact JSON payload bytes. The private key remains in the test issuer process; only the public key is inserted into a private verification-key table. PostgreSQL parses the signed JSON only after the C function verifies the original bytes.

The test-only SQL verifier checks:

- issuer, audience, key ID and deployment ID;
- database OID, backend PID and `pg_current_xact_id()`;
- issue/expiry time and a maximum 60-second validity interval;
- signature validity and an 8 KiB payload bound.

The external-issuer integration test passed valid claims and rejected modified signatures, wrong backend, wrong transaction, wrong database, wrong deployment/audience, wrong issuer, expired tokens, replay after COMMIT, replay after ROLLBACK, and replay from another backend. It also verified that savepoint rollback preserves the outer transaction context and that a `READ ONLY` transaction can obtain an XID and use the signed context.

RLS returned only the signed tenant's rows even after the test runtime forged the legacy `app.tenant_id`, `app.principal_id`, and `app.caller_id` GUCs. The runtime could execute the SECURITY DEFINER context verifier but could neither read the verification-key table nor invoke the low-level C function directly.

This is an external Python issuer simulation, not the final Rust ContextIssuer. The token format, SQL contract and transaction semantics are now exercised end-to-end without pgsodium, but production integration is still pending.

## Limitations and remaining gates

- This is new Qembed-maintained native C code and needs independent security review, fuzzing, ABI/build provenance, a supported PostgreSQL matrix, and packaging/update policy.
- The Python issuer is a test harness; the Rust signing component, key storage/KMS/HSM integration, canonical token contract, and Rust connection-pool lifecycle are not implemented.
- No real second-cluster replay test, key rotation/revocation, Caller delegation/revocation race, issuer outage, retry orchestration, or pool reuse test is included.
- The RLS policies are test fixtures, not production policies. Production RLS migration and representative workload benchmarking remain required.
- The prototype is in `qembed-sql` only for evaluation; if adopted, extension source/package ownership and release lifecycle must be decided explicitly.

Compare this branch with [the pgsodium prototype PR #68](https://github.com/qembed/qembed-sql/pull/68). Neither prototype is production-approved.

## Validation evidence

- [Minimal verifier workflow run #12](https://github.com/qembed/qembed-sql/actions/runs/45024110220) passed on PostgreSQL 19 / pgvector 0.8.7 using Debian Bookworm libsodium 1.0.18.
- [SQL smoke run #286](https://github.com/qembed/qembed-sql/actions/runs/45024110210) passed on the same code head.