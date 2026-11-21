# RT-050 — Cryptographically verified transaction context

**Status:** Proposed architecture plan; intentionally not implemented  
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
- The PostgreSQL verification mechanism is an explicit prototype gate. Do not assume that core PostgreSQL or `pgcrypto` provides the required Ed25519 / generic signature verification. Evaluate a vetted, maintained extension or another narrowly scoped verification mechanism on the actual PostgreSQL 19 target.
- HMAC is a fallback only if the shared-secret placement, database exposure, rotation and compromise assumptions are explicitly accepted. It is not equivalent to public-key verification.
- No SQL function may mint or sign a token. Database functions only verify and expose claims.
- Key rotation, key identifiers, expiry, clock-skew policy and emergency key revocation must be specified before implementation.

## 4. Transaction binding and replay

A token must be bound to both the database backend and the exact transaction. A token copied to another backend or transaction must fail verification.

The prototype must establish the precise ordering needed to obtain the backend PID and transaction ID before token issuance and before any RLS-protected query. It must also verify behavior for read-only transactions and transaction-ID assignment semantics.

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
- [ ] Prototype public-key signature verification on PostgreSQL 19 using a vetted mechanism; document operational and supply-chain implications.
- [ ] Prove transaction binding to backend PID and transaction ID, including retries and pool reuse.
- [ ] Decide whether atomic one-time-use is required in addition to transaction binding.
- [ ] Specify issuer authentication, Caller delegation validation, revocation behavior, key rotation and outage behavior.
- [ ] Produce a Rust transaction API design and migration/compatibility plan.
- [ ] Add adversarial SQL tests before any production migration.
- [ ] Obtain explicit project-owner approval of the complete design.

**Implementation status:** none. This branch is a parked design plan; it does not alter `master`, deployed SQL, or the current Rust transaction contract.
