# RT-050 — Cryptographically verified transaction context

**Status:** Accepted remediation architecture; minimal C verifier and canonical signed-context SQL migration are implemented in the PR #74 candidate stack (including PRs #71/#72); PostgreSQL 19 end-to-end validation passed on PR #72; the stack is not merged into `master` and production release gates remain open  
**Priority:** P0 remediation — QSA-003 remains open until production SQL/Rust migration and release gates pass  
**Scope:** QSA-003 trust boundary; PostgreSQL identity context, Rust transaction setup, RLS policies, deployment and test contracts  
**Branch:** `architecture/rt-050-signed-transaction-context`  
**Decision owner:** Project owner (accepted 2026-11-23)

## 1. Problem

The current schema uses the custom PostgreSQL settings `app.tenant_id`, `app.principal_id`, and `app.caller_id` as inputs to RLS and authorization functions. These settings are writable by a session using `qembed_runtime`. `SET LOCAL` limits lifetime but does not authenticate the value.

Therefore the current design protects against accidental missing scope and application mistakes when the trusted transaction wrapper is used correctly. It does not provide an independent database boundary against arbitrary SQL executed as `qembed_runtime`.

This ADR records the accepted replacement of independently writable identity settings with one cryptographically verifiable transaction-context token. The Rust issuer/transaction path and a PostgreSQL 19 verifier feasibility prototype exist; the canonical production SQL migration is still pending.

## 2. Proposed direction

A trusted Context Issuer authenticates the Principal, validates that the selected Caller is currently delegated to that Principal in the requested tenant, and issues a signed context token for one database transaction.

The Rust transaction layer begins a database transaction, obtains the transaction binding (backend PID and transaction ID), obtains a token bound to that transaction, and passes the token to PostgreSQL. A narrowly privileged verifier validates the token. RLS and authorization helpers consume only the verified claims, never raw identity GUCs.

Conceptual claims:

- tenant ID;
- Principal ID;
- exact selected Caller ID;
- PostgreSQL backend PID;
- PostgreSQL transaction ID;
- issued-at and expiry;
- nonce / unique token identifier;
- issuer, audience and signing-key identifier.

The token is carried in a single setting such as `app.context_token`. The setting itself remains mutable and visible to SQL in the same session; security comes from signature verification and transaction binding, not from secrecy or immutability of the GUC.

## 3. Trust boundaries and key handling

- The Context Issuer is outside the arbitrary-SQL execution path and does not expose a signing operation that arbitrary SQL can invoke with attacker-chosen claims.
- The issuer holds the signing private key. PostgreSQL should ideally hold only a public verification key.
- An asymmetric signature scheme is preferred because compromise of the database runtime role does not reveal a signing secret.
- The PostgreSQL verification mechanism was an explicit prototype gate. The pgsodium 3.1.11 Ed25519 API has now passed a PostgreSQL 19 / pgvector 0.8.7 feasibility workflow. This is not vendor certification or production supply-chain approval; see the prototype evidence in section 10.
- HMAC is a fallback only if the shared-secret placement, database exposure, rotation and compromise assumptions are explicitly accepted. It is not equivalent to public-key verification.
- No SQL function may mint or sign a token. Database functions only verify and expose claims.
- Key rotation, key identifiers, expiry, clock-skew policy and emergency key revocation must be specified before implementation.

## 4. Transaction binding and replay

A token must be bound to both the database backend and the exact transaction. A token copied to another backend or transaction must fail verification.

The PostgreSQL feasibility probe established that a token bound to `pg_backend_pid()` and `pg_current_xact_id()` is accepted only in its issuing backend and transaction. It passed commit/rollback replay, savepoint rollback, independent-backend replay, and read-only transaction-ID acquisition. Rust PR #93 implemented the ContextIssuer and signed transaction bootstrap, including transaction-bound Caller resolution and PostgreSQL integration tests for transaction/pool lifecycle. The canonical SQL migration is now in clean candidate PR #74 and has passed the predecessor PR #72 end-to-end workflow; merge/revalidation on current `master` and combined Rust/SQL validation remain pending.

A nonce alone does not prevent replay. If single-use semantics are required beyond backend/transaction binding, implement and test an atomic one-time-use mechanism; do not claim replay prevention merely because a nonce exists.

The issuer must bind the exact selected Caller, not just the Principal. PostgreSQL may additionally re-check that the Principal, Caller and delegation are still active so revocation semantics remain enforceable.

## 5. Database integration requirements

- RLS policies and security helpers use only claims returned by the verified-context function.
- Raw `app.tenant_id`, `app.principal_id`, and `app.caller_id` settings are removed as authorization inputs; setting them manually has no effect.
- The verifier is a narrow `SECURITY DEFINER` function with a fixed safe `search_path`, including `pg_temp` last, and minimum grants.
- The runtime role cannot read private key material, change trusted verification keys, bypass the verifier, or execute an issuer/signing function.
- The runtime role remains non-owner, `NOSUPERUSER`, `NOBYPASSRLS`, and outside privileged worker/definer role memberships.
- Existing `qembed_worker` separation remains independent; signed tenant context must not accidentally grant worker-wide discovery.
- Pool reset, commit, rollback, savepoints and connection reuse must not leak a previously verified context.
- Existing delegation revocation locking and Principal/Caller lifecycle checks remain in force.

## 6. Rust integration requirements

**Implemented in Rust PR #93:** the transaction API establishes a READ COMMITTED transaction, reads backend PID / transaction ID / database OID, resolves and locks the exact Caller delegation where required, signs the claims locally, and installs `app.context_token` transaction-locally before scoped queries. `PgContext` exposes Principal-only and Caller-scoped transaction entry points. The legacy `begin_tenant_transaction` helper remains for compatibility/tests, but current production source has no caller. The SQL candidate migration must be reviewed and deliberately integrated into `master` before coordinated deployment.

The public API must not allow request DTOs or callers to supply tenant, Principal, Caller, backend PID, transaction ID, expiry, or signature claims. Those values originate from authenticated application state, database transaction state, and the issuer.

The Rust implementation defines bounded local signing (no remote KMS call while delegation locks are held), transaction binding, and failure on issuer/signing/database errors. The ContextIssuer is not yet wired to the KMCP lifecycle/provider adapters. No fallback to forgeable identity GUCs is permitted. SQL must not accept a mixed signed/legacy identity path.

## 7. Required prototype and acceptance tests

Prototype on PostgreSQL 19 before changing production schema or Rust contracts.

Negative tests under the actual `qembed_runtime` role:

1. Setting fake legacy tenant / Principal / Caller GUCs does not change effective identity.
2. A token with altered claims or signature is rejected.
3. A valid token for a different backend PID is rejected.
4. A valid token for a different transaction ID is rejected.
5. A token with an expired timestamp, unknown key ID, wrong issuer or wrong audience is rejected.
6. A token for Caller B cannot be substituted when the issuer authorized Caller A.
7. Runtime cannot read or alter verification key material or invoke signing.
8. A token from a committed or rolled-back transaction cannot authorize a later transaction on the same pooled connection.
9. A tenant cannot use the token to invoke cross-tenant worker functions.
10. Context is cleared or becomes unusable after commit, rollback, error and pool reuse.

Positive tests:

- A correctly issued token authorizes only its tenant / Principal / exact Caller context.
- Delegation revocation and Principal/Caller deactivation retain their defined race and lifecycle semantics.
- Normal runtime operations continue to work with least-privilege grants.

Tests must run with at least two tenants and two Callers, using the same pooled connection across commit and rollback boundaries. Include catalog assertions for role attributes, memberships, verifier ownership, function configuration and grants.

## 8. Explicit non-goals and residual risks

This design does not protect against compromise of the Context Issuer, its private signing key, or the application process that can legitimately request tokens for identities it controls. It does not protect against PostgreSQL superuser compromise.

It is not a substitute for parameterized SQL, least privilege, SECURITY DEFINER hardening, worker-role separation or application input validation.

Per-tenant PostgreSQL login roles and separate connection pools remain a possible stronger / complementary isolation model, but are not selected in this proposal because of their operational and pooling cost. They may be evaluated separately if the threat model requires database-native tenant identities.

## 9. Decision gates before implementation

- [x] Map all current reads and writes of the three identity GUCs and every policy/function that consumes them; see `docs/QSA-003_LEGACY_GUC_CONSUMER_MAP.md` and SQL PR #70.
- [x] Evaluate the pgsodium Ed25519 alternative on PostgreSQL 19; it is retained as historical comparison evidence only. It is not the selected implementation.
- [x] Demonstrate the narrow backend/transaction/database/deployment binding predicate, including replay after commit/rollback, independent-backend replay, savepoint semantics, and read-only transaction-ID acquisition.
- [x] Implement the signed transaction bootstrap and verify commit/rollback, backend/transaction binding, connection-pool reuse and tenant-context isolation in Rust PR #93; continue combined testing after the canonical SQL migration.
- [ ] Decide whether atomic one-time-use is required in addition to backend/transaction binding.
- [ ] Specify issuer authentication, Caller delegation validation, revocation behavior, key rotation and outage behavior.
- [x] Prototype a minimal C verifier alternative that needs no pgsodium preload or server root key.
- [x] Select the minimal C verifier in PR #74 as the RT-050 implementation candidate; pgsodium PR #68 is not selected for this implementation track. This is not production approval.  
- [ ] Complete independent security review, supply-chain assessment, fuzzing, packaging/provenance work and supported PostgreSQL matrix before production approval.
- [ ] Integrate the one-verification-per-statement `InitPlan` pattern into actual RLS helpers and benchmark representative production policies/data.
- [x] Implement the Rust transaction API and compatibility boundary in Rust PR #93; integrate the canonical SQL candidate into `master` and validate coordinated deployment remain pending.
- [x] Add current-risk exploit-demonstration tests in SQL PR #70; inverted negative tests against the signed-context schema remain required before production migration.
- [ ] Obtain explicit project-owner approval of the complete design.

## 10. PostgreSQL 19 feasibility prototype evidence

The following is experimental evidence only. It does not implement the proposed production schema or Rust contract.

- Historical alternative [SQL PR #68](https://github.com/qembed/qembed-sql/pull/68) builds pgsodium 3.1.11 from exact source commit `a8b8a2739bab1f7a07445b1c911e2bd1abf67784` against PostgreSQL 19 and verifies the Ed25519 detached-signature API. The source commit signature is valid; the annotated `v3.1.11` tag object is unsigned.
- pgsodium 3.1.11's IPcrypt implementation requires libsodium 1.0.22 symbols; Debian Bookworm's libsodium 1.0.18 is insufficient. The workflow builds libsodium 1.0.22 from pinned source and asserts that pgsodium resolves `libsodium.so.26`.
- The test-only verifier is `SECURITY DEFINER`, uses a fixed `search_path` with `pg_temp` last, reads public keys from a table inaccessible to `qembed_runtime`, and grants the runtime role verification but no signing or key-generation capability. The RLS benchmark also demonstrates the importance of an uncorrelated scalar subquery / `InitPlan` to avoid repeated verification per row.
- [Prototype workflow run #31](https://github.com/qembed/qembed-sql/actions/runs/45020806755) and [PostgreSQL 19 / pgvector smoke run #246](https://github.com/qembed/qembed-sql/actions/runs/45020806694) passed on the tested code head `bcf65cf6141af8812849705d741f328d5e5141dc`.

The test-only verifier rejects modified signatures, expired tokens, wrong backend PID, wrong database OID, wrong deployment/audience, replay after COMMIT, replay after ROLLBACK on the same backend, and replay from an independent connection. It confirms that forged legacy identity GUCs do not alter the signed claims, that savepoint rollback preserves the valid outer-transaction context, and that `pg_current_xact_id()` can be obtained in a `READ ONLY` transaction.

A test-only RLS experiment compared direct policy evaluation with an uncorrelated scalar subquery. On identical 10,000-row tables (5,000 rows for the signed tenant, no tenant index), the direct verifier helper took 855.463 ms and 30,064 shared buffer hits; the scalar-subquery form produced an explicit `InitPlan` and took 1.143 ms with 67 shared buffer hits. This is a CI microbenchmark, not a production guarantee, but it establishes that the production RLS design must preserve one context verification per statement rather than repeat signature verification per scanned row.

The CI harness also had to put pgsodium in `shared_preload_libraries`: its DDL event trigger reads `pgsodium.enable_event_trigger`, which pgsodium defines during shared preload. Preload also requires a getkey script and loads a root key into server memory. CI uses a test-only provider that returns a fresh random root key at startup without persisting it. This is appropriate only because the probe does not use pgsodium server-managed key derivation or key-ID APIs; production must explicitly forbid those APIs if using an ephemeral key, or securely manage a durable root-key lifecycle, or select another verifier deployment model. The Ed25519 verifier itself uses public verification keys and does not use the pgsodium root key.

**Not yet proven:** a real Context Issuer and private-key isolation; production deployment-ID provisioning and cross-cluster uniqueness; token encoding/canonicalization shared by Rust and SQL; Caller delegation and revocation races; key rotation/revocation; issuer outage; RLS policy integration and per-row verification cost; retry/error handling; and actual connection-pool reset/reuse in Rust. The test issues tokens in a privileged SQL test session, uses a test-only verifier and fixtures, and does not replace production identity GUCs.

A nonce is present in the probe payload but is not treated as single-use replay protection. Transaction binding is the tested replay boundary; any stronger one-time-use requirement remains a separate decision.

## 11. Alternative minimal verifier prototype

The project owner selected the minimal C verifier in [Draft SQL PR #74](https://github.com/qembed/qembed-sql/pull/74) as the implementation candidate for RT-050. PR #68 is the unselected pgsodium alternative and should remain parked; do not develop both paths in parallel. PR #74 is a clean feasibility/migration candidate, not production approval or approval to deploy it. The PR prototypes a Qembed-maintained PostgreSQL C extension with exactly one SQL function that calls libsodium `crypto_sign_verify_detached`. It passed PostgreSQL 19 CI using Debian Bookworm libsodium 1.0.18 and does not require pgsodium, `shared_preload_libraries`, a getkey script, or a server root key. It exposes no signing, key-generation, encryption, key-derivation, or DDL event-trigger API. The function rejects messages larger than 8 KiB.

The candidate stack now exercises the SQL transaction-context contract against the canonical clean-install schema in PR #72. The merged PR #72 workflow #45061320489 passed on exact head `e7759dd7178b9ac703414edc067601e24db18f5f`; this validation is still branch-only until PR #74 is integrated into `master`. A test-only Python issuer uses ctypes/libsodium outside PostgreSQL to generate a keypair and sign the exact JSON payload bytes; only the public key is stored in a private verification-key table. The SQL verifier checks issuer, audience, key ID, deployment ID, database OID, backend PID, transaction ID, issue/expiry time and signature. The runtime role cannot read the key table or invoke the low-level C function directly.

[Minimal verifier workflow run #14](https://github.com/qembed/qembed-sql/actions/runs/45024432606) passed valid context and rejected modified signatures, wrong backend/transaction/database/deployment/issuer, expired tokens, replay after COMMIT/ROLLBACK, and replay from another backend. It also verified savepoint behavior, `READ ONLY` transaction binding, and RLS isolation despite forged legacy identity GUCs. This is an external Python issuer simulation, not the final Rust ContextIssuer.

The test-only primitive RLS fixture measured 7.280 ms direct versus 0.511 ms with an `InitPlan` on 10,000 rows in run #12. This is not a production guarantee. It isolates the C primitive and uses a fixed RFC vector; the full signed-context integration separately exercises JSON parsing, key lookup and transaction binding. These numbers are not directly comparable to the pgsodium RLS fixture, which measured a larger PL/pgSQL/key-table/claim-parsing path.

The minimal extension removes pgsodium's preload/root-key operational dependency and narrows the exposed API. It is the selected implementation candidate, but creates Qembed-maintained native C code that still needs independent security review, fuzzing, packaging/provenance and a supported PostgreSQL matrix. The architectural selection is made; production approval is not.

**Still not proven:** actual cross-cluster replay with two clusters; production key rotation/revocation and external KMCP/OIDC/KMS/HSM custody; independent security review and C-extension fuzzing; ABI/build provenance, packaging/update policy and supported PostgreSQL matrix; representative production RLS workload performance; canonical SQL RLS/function migration and inverted spoofing tests; coordinated deployment and independent adversarial retest.

**Implementation status:** Rust signed-context transaction entry points are merged in `qembed-object-runtime/main` (PR #93). SQL PR #74 now contains the verifier, key lifecycle, Principal-only token semantics and canonical signed-context RLS migration; PRs #71/#72 were merged into that candidate branch and the PostgreSQL 19 end-to-end workflow #45061320489 passed on PR #72 head `e7759dd7178b9ac703414edc067601e24db18f5f`. This entire stack remains unmerged into SQL `master`; `master` still uses legacy identity-GUC consumers. QSA-003 remains `IN_PROGRESS`; no production deployment is approved.
