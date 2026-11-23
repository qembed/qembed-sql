# QSA-003 — minimal Ed25519 verifier prototype

**Status:** Selected feasibility candidate for QSA-003/RT-050; not production-approved. No canonical production RLS migration has been merged.

## Design

This prototype exposes one PostgreSQL C function:

`qembed_crypto.qembed_context_verify_detached(signature bytea, message bytea, public_key bytea) -> boolean`

It calls libsodium `crypto_sign_verify_detached`, accepts only 64-byte signatures and 32-byte public keys, and rejects messages larger than 8 KiB. It exposes no key-generation, signing, encryption, key-derivation, or event-trigger API. The SQL extension revokes EXECUTE from PUBLIC; the runtime role is not granted direct access to the low-level function.

The C module initializes libsodium when loaded by a backend. It does not require `shared_preload_libraries`, pgsodium, a DDL event trigger, a getkey script, or a server root key.

## PostgreSQL 19 test coverage

The canonical workflow builds against Debian Bookworm libsodium and PostgreSQL 19, then performs two probes.

### Primitive and RLS plan probe

- verifies the RFC 8032 Ed25519 test vector;
- rejects a modified signature, modified message, invalid signature length, invalid public-key length, and payloads larger than 8 KiB;
- confirms pgsodium is not installed and `shared_preload_libraries` remains empty;
- confirms the extension exposes exactly one SQL function;
- confirms the runtime role cannot call the low-level verifier directly or create objects in the extension schema;
- compares direct verifier evaluation with an uncorrelated scalar subquery planned as an `InitPlan`.

### Full transaction-bound context probe

A separate external Python test issuer uses libsodium to generate an Ed25519 keypair and signs the exact UTF-8 JSON bytes produced by the pinned RFC 8785 JCS implementation (`rfc8785`). The private key remains in the issuer process; only the public key is inserted into a private verification-key table.

The test issuer emits the same wire envelope as Rust:

`app.context_token = qctx1:<payload-hex>:<signature-hex>`

The SQL verifier checks signature, key lifecycle, fixed claims, backend/transaction/database/deployment binding, expiry, replay, savepoint rollback, read-only transactions, typed accessors, least privilege and RLS isolation despite forged legacy identity GUCs. The detailed protocol and transaction cases are documented in the SQL probe and roadmap.

Rust PR #118 exercises the real Rust `ContextIssuer` against the canonical clean-install schema plus this SQL migration candidate. That is integration evidence for the Draft candidate; SQL `master` remains unchanged.

## Fuzzing

The production PostgreSQL wrapper and standalone libFuzzer target call the same `qembed_context_verify_detached_bytes` implementation in `qembed_context_verify_core.h`. The harness therefore exercises the same signature/key/message length checks and libsodium verification call used by the extension.

The fast PR smoke campaign remains bounded to 60 seconds. The additional `verifier-libfuzzer-extended` job in `.github/workflows/minimal-verifier-prototype.yml` runs a 10-minute libFuzzer campaign with Clang's libFuzzer, AddressSanitizer and UndefinedBehaviorSanitizer. Its retained seed corpus includes the RFC 8032 valid empty-message vector, zeroed signature/key input, truncated signature/key inputs, and an 8,193-byte message that exercises the production 8 KiB rejection boundary. The maximum generated input is 16,384 bytes so the fuzzer can reach that boundary and explore malformed lengths beyond it.

The workflow retains the generated corpus, any crash artifacts, the complete fuzz log and compiler/libsodium/runner metadata as a 90-day GitHub Actions artifact. Any crash or sanitizer finding fails the job; it must be minimized, committed as a regression seed, and fixed before release. This campaign is stronger repeatable evidence, but it is not a substitute for a longer corpus campaign, coverage review or independent security assessment.

## Limitations and remaining gates

- This is new Qembed-maintained native C code and still needs independent security review, ABI/build provenance, a supported PostgreSQL matrix, and packaging/update policy.
- The fuzz campaign is time-bounded and uses GitHub-hosted runners; its artifact retention is finite and does not replace an independently maintained long-term corpus.
- The Python issuer is a test harness; key storage/KMS/HSM integration and the Rust connection-pool lifecycle are not tested end-to-end here.
- External KMCP service, OIDC/SSO authorization, KMS/HSM custody, multi-instance signer rollout, external immutable audit sink, multi-cluster replay/outage tests and production provisioning remain outside this prototype.
- RLS policies are test fixtures, not production policies. Production migration and representative workload benchmarking remain required.
- Extension source/package ownership and release lifecycle must be decided explicitly.

The pgsodium alternative in PR #68 was not selected. This narrow C verifier remains a feasibility prototype and is not production-approved.
