# RT-050 — Cryptographically verified transaction context

**Status:** Proposed architecture plan; PostgreSQL 19 verifier/binding feasibility prototyped, production design intentionally not implemented  
**Priority:** Deferred — revisit after completion of the SQL adversarial audit  
**Scope:** QSA-003 trust boundary; PostgreSQL identity context, Rust transaction setup, RLS policies, deployment and test contracts  
**Branch:** `architecture/rt-050-signed-transaction-context`  
**Decision owner:** Project owner

## 1. Problem

The current schema uses the custom PostgreSQL settings `app.tenant_id`, `app.principal_id`, and `app.caller_id` as inputs to RLS and authorization functions. These settings are writable by a session using `qembed_runtime`. `SET LOCAL` limits lifetime but does not authenticate the value.

Therefore the current design protects against accidental missing scope and application mistakes when the trusted transaction wrapper is used correctly. It does not provide an independent database boundary against arbitrary SQL executed as `qembed_runtime`.

This ADR explores replacing those independently writable identity settings with one cryptographically verifiable transaction-context token.

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

The feasibility probe established that a token bound to `pg_backend_pid()` and `pg_current_xact_id()` is accepted only in its issuing backend and transaction. It also passed commit/rollback replay, savepoint rollback, independent-backend replay, and read-only transaction-ID acquisition. The Rust-side ordering, retry orchestration and actual pool lifecycle still need to be designed and tested before production implementation.

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

The Rust transaction API must establish the transaction first, obtain the exact database binding, request a token from the trusted issuer, install the token, and only then execute scoped queries.

The public API must not allow request DTOs or callers to supply tenant, Principal, Caller, backend PID, transaction ID, expiry, or signature claims. Those values originate from authenticated application state, database transaction state, and the issuer.

The implementation must define failure behavior for issuer unavailability, expired tokens, key rotation, transaction restart/retry, nested transactions and connection-pool reuse. No fallback to the current forgeable GUC identity is permitted unless an explicit temporary compatibility decision is approved.

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

- [ ] Map all current reads and writes of the three identity GUCs and every policy/function that consumes them.
- [x] Prototype pgsodium Ed25519 verification on PostgreSQL 19 and least-privilege verifier execution. The feasibility result is recorded in section 10; production supply-chain and vendor-support approval remain pending.
- [x] Demonstrate the narrow backend/transaction/database/deployment binding predicate, including replay after commit/rollback, independent-backend replay, savepoint semantics, and read-only transaction-ID acquisition.
- [ ] Complete retry orchestration, error handling and connection-pool lifecycle tests in the Rust transaction layer.
- [ ] Decide whether atomic one-time-use is required in addition to backend/transaction binding.
- [ ] Specify issuer authentication, Caller delegation validation, revocation behavior, key rotation and outage behavior.
- [x] Prototype a minimal C verifier alternative that needs no pgsodium preload or server root key.
- [ ] Select the verifier implementation after independent security review, supply-chain assessment, and explicit evaluation of pgsodium's preload/root-key lifecycle versus Qembed's native-code maintenance burden.
- [ ] Integrate the one-verification-per-statement `InitPlan` pattern into actual RLS helpers and benchmark representative production policies/data.
- [ ] Produce a Rust transaction API design and migration/compatibility plan.
- [ ] Add adversarial SQL tests before any production migration.
- [ ] Obtain explicit project-owner approval of the complete design.

## 10. PostgreSQL 19 feasibility prototype evidence

The following is experimental evidence only. It does not implement the proposed production schema or Rust contract.

- [SQL PR #68](https://github.com/qembed/qembed-sql/pull/68) builds pgsodium 3.1.11 from exact source commit `a8b8a2739bab1f7a07445b1c911e2bd1abf67784` against PostgreSQL 19 and verifies the Ed25519 detached-signature API. The source commit signature is valid; the annotated `v3.1.11` tag object is unsigned.
- pgsodium 3.1.11's IPcrypt implementation requires libsodium 1.0.22 symbols; Debian Bookworm's libsodium 1.0.18 is insufficient. The workflow builds libsodium 1.0.22 from pinned source and asserts that pgsodium resolves `libsodium.so.26`.
- The test-only verifier is `SECURITY DEFINER`, uses a fixed `search_path` with `pg_temp` last, reads public keys from a table inaccessible to `qembed_runtime`, and grants the runtime role verification but no signing or key-generation capability. The RLS benchmark also demonstrates the importance of an uncorrelated scalar subquery / `InitPlan` to avoid repeated verification per row.
- [Prototype workflow run #31](https://github.com/qembed/qembed-sql/actions/runs/45020806755) and [PostgreSQL 19 / pgvector smoke run #246](https://github.com/qembed/qembed-sql/actions/runs/45020806694) passed on the tested code head `bcf65cf6141af8812849705d741f328d5e5141dc`.

The test-only verifier rejects modified signatures, expired tokens, wrong backend PID, wrong database OID, wrong deployment/audience, replay after COMMIT, replay after ROLLBACK on the same backend, and replay from an independent connection. It confirms that forged legacy identity GUCs do not alter the signed claims, that savepoint rollback preserves the valid outer-transaction context, and that `pg_current_xact_id()` can be obtained in a `READ ONLY` transaction.

A test-only RLS experiment compared direct policy evaluation with an uncorrelated scalar subquery. On identical 10,000-row tables (5,000 rows for the signed tenant, no tenant index), the direct verifier helper took 855.463 ms and 30,064 shared buffer hits; the scalar-subquery form produced an explicit `InitPlan` and took 1.143 ms with 67 shared buffer hits. This is a CI microbenchmark, not a production guarantee, but it establishes that the production RLS design must preserve one context verification per statement rather than repeat signature verification per scanned row.

The CI harness also had to put pgsodium in `shared_preload_libraries`: its DDL event trigger reads `pgsodium.enable_event_trigger`, which pgsodium defines during shared preload. Preload also requires a getkey script and loads a root key into server memory. CI uses a test-only provider that returns a fresh random root key at startup without persisting it. This is appropriate only because the probe does not use pgsodium server-managed key derivation or key-ID APIs; production must explicitly forbid those APIs if using an ephemeral key, or securely manage a durable root-key lifecycle, or select another verifier deployment model. The Ed25519 verifier itself uses public verification keys and does not use the pgsodium root key.

**Not yet proven:** a real Context Issuer and private-key isolation; production deployment-ID provisioning and cross-cluster uniqueness; token encoding/canonicalization shared by Rust and SQL; Caller delegation and revocation races; key rotation/revocation; issuer outage; RLS policy integration and per-row verification cost; retry/error handling; and actual connection-pool reset/reuse in Rust. The test issues tokens in a privileged SQL test session, uses a test-only verifier and fixtures, and does not replace production identity GUCs.

A nonce is present in the probe payload but is not treated as single-use replay protection. Transaction binding is the tested replay boundary; any stronger one-time-use requirement remains a separate decision.

## 11. Alternative minimal verifier prototype

A separate [Draft PR #69](https://github.com/qembed/qembed-sql/pull/69) prototypes a Qembed-maintained PostgreSQL C extension with exactly one SQL function that calls libsodium `crypto_sign_verify_detached`. It passed PostgreSQL 19 CI using Debian Bookworm libsodium 1.0.18 and does not require pgsodium, `shared_preload_libraries`, a getkey script, or a server root key. It exposes no signing, key-generation, encryption, key-derivation, or DDL event-trigger API.

The RFC 8032 primitive test passes and altered signatures/messages and invalid key/signature lengths are rejected. The test-only RLS wrapper measured 7.377 ms direct versus 0.480 ms with an `InitPlan` on 10,000 rows. This fixture uses a fixed test vector and isolates the C primitive; it does not parse signed claims or perform key-table lookup. It is therefore not directly comparable to the pgsodium RLS fixture, which includes PL/pgSQL, key-table access and JSON claim parsing.

The minimal extension removes pgsodium's preload/root-key operational dependency and narrows the exposed API, but it creates Qembed-maintained native C code that needs independent security review, fuzzing, packaging/provenance and a supported PostgreSQL matrix. Neither implementation is selected. The decision must compare the trusted-code burden of maintaining the small C extension against pgsodium's broader API, source provenance and preload/root-key lifecycle.


**Implementation status:** none. This branch remains a proposed design plan; it does not alter `master`, deployed SQL, or the current Rust transaction contract.
