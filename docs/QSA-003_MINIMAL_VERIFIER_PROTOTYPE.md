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

In run #13, the 10,000-row primitive fixture measured 7.280 ms for direct C verification versus 0.511 ms through the `InitPlan` form (5,000 visible rows, no tenant index). This is a CI microbenchmark, not a production performance guarantee; timing varies with runner load.

### Full transaction-bound context probe

A separate external Python test issuer uses libsodium to generate an Ed25519 keypair and signs the exact UTF-8 JSON bytes produced by the pinned RFC 8785 JCS implementation (`rfc8785==0.1.4`). This replaces the earlier `json.dumps(sort_keys=True)` approximation, which is not a general RFC 8785 implementation. The private key remains in the issuer process; only the public key is inserted into a private verification-key table.

The test issuer now emits the same wire envelope as Rust:

`app.context_token = qctx1:<payload-hex>:<signature-hex>`

The SQL verifier:
- rejects unknown envelope versions, malformed/lowercase-hex violations, invalid signature lengths and payloads above 8 KiB;
- uses the untrusted `key_id` only to locate a candidate public key, verifies the signature over the original payload bytes, and trusts no claim until verification succeeds;
- enforces verification-key lifecycle states: `staged` is not verifiable; `active` accepts tokens issued after activation; `retired` rejects newly issued tokens but accepts pre-retirement tokens only until a bounded verification deadline; `revoked` rejects all tokens immediately;
- exposes narrowly privileged `stage_verification_key`, `activate_verification_key`, `retire_verification_key`, and `revoke_verification_key` mutation operations plus `list_verification_keys` and `get_key_lifecycle_operation` metadata/audit readers; the dedicated `qembed_key_control_plane` login has EXECUTE-only access and cannot read or mutate registry/audit tables directly; runtime has no registry, audit, low-level verifier, or management/read-function privileges;
- writes an append-only lifecycle audit event and an export-outbox row in the same transaction as every key state change; the separate `qembed_key_audit_exporter` identity can only list pending events, acknowledge delivery, and record sanitized failures through SECURITY DEFINER functions, with no direct audit/outbox table access; control-plane metadata reads expose export status;
- makes audit export at-least-once and idempotent by event ID, keeps failed deliveries pending for retry, and prevents changes to delivered outbox records;
- enforces monotonic transitions (`staged -> active -> retired -> revoked`, with `staged -> revoked` and `active -> revoked` emergency paths), immutable key identity/public material, append-only audit rows, idempotency bound to the original request payload, distinct operator/approver subjects for activation and retirement, and a 120-second to one-hour retirement grace;
- validates the exact 14 version-1 string claims, lowercase UUID syntax (including nonce), issuer, audience, key ID, deployment ID, database OID, backend PID, transaction ID, issue/expiry times and the 60-second maximum lifetime;
- exposes typed tenant, Principal and Caller accessors;
- reads authorization context only from `app.context_token`.

The integration test also attempts to install the maximum-size token envelope to verify PostgreSQL GUC capacity for the documented 8 KiB payload limit. If PostgreSQL rejects that value, the protocol's hex envelope and payload bound must be revisited together with the Rust issuer; do not silently truncate or switch encodings.

The verified-context function uses statement-stable time and is declared STABLE so the uncorrelated scalar subquery in the RLS policy can be planned as an InitPlan. The integration test asserts that plan shape directly, then rejects modified payload/signature, unknown envelope version, wrong backend/transaction/database/deployment/issuer/version, expired tokens, replay after COMMIT/ROLLBACK and replay from another backend. It verifies savepoint rollback, read-only transactions, typed claim accessors, least privilege, and RLS isolation despite forged legacy identity GUCs.

This is still an external test issuer, not an invocation of the Rust `ContextIssuer` itself. The use of RFC 8785 in Python tests exercises the same canonicalization standard but does not replace a Rust-to-PostgreSQL integration test using `serde_jcs`. The SQL role/function fixture is not a production control plane or a canonical production migration.

## Limitations and remaining gates

- This is new Qembed-maintained native C code and needs independent security review, fuzzing, ABI/build provenance, a supported PostgreSQL matrix, and packaging/update policy.
- The Python issuer is a test harness; key storage/KMS/HSM integration and the Rust connection-pool lifecycle are not tested end-to-end here.
- The lifecycle fixture now exercises staged registration, explicit activation, database-side retirement/revocation, a dedicated control-plane database identity, least-privilege management functions and append-only audit. It does not implement the external KMCP service, OIDC/SSO authorization, KMS/HSM custody, proof-of-possession at the service boundary, coordinated multi-instance signer rollout, or production deployment provisioning.
- No real second-cluster replay test, issuer outage, or retry orchestration test is included.
- The RLS policies are test fixtures, not production policies. Production RLS migration and representative workload benchmarking remain required.
- The prototype is in `qembed-sql` only for evaluation; if adopted, extension source/package ownership and release lifecycle must be decided explicitly.

Compare this branch with [the pgsodium prototype PR #68](https://github.com/qembed/qembed-sql/pull/68). Neither prototype is production-approved.

## Validation evidence

- [Minimal verifier workflow run #14](https://github.com/qembed/qembed-sql/actions/runs/45024432606) passed on PostgreSQL 19 / pgvector 0.8.7 using Debian Bookworm libsodium 1.0.18.
- [SQL smoke run #291](https://github.com/qembed/qembed-sql/actions/runs/45024432592) passed on the earlier prototype head. The new qctx1/JCS contract requires a fresh workflow run before it can be considered validated.
