# QSA-003 — legacy identity-GUC consumer map and migration contract

**Status:** Source map complete; current-risk regression passed on PostgreSQL 19; signed-context migration in progress  
**Canonical schema baseline:** `qembed_m0_v2_3_3_clean_schema.sql`, blob `1971d97a13a07561d1319e0287c6c129e3276851`  
**Runtime companion:** `qembed/qembed-object-runtime`, current `main` source  
**Purpose:** enumerate every SQL identity-GUC read/write found in the canonical clean-install schema and connect it to the Rust transaction bootstrap.

This document records the current, intentionally weak trust boundary. It does not claim the legacy GUC model is secure, and it does not close QSA-003.

## 1. Threat-model decision

The selected remediation is a signed, transaction-bound context token. The target threat model includes arbitrary SQL execution under the ordinary `qembed_runtime` database role **for the purpose of preventing an attacker from changing tenant, Principal or Caller identity by writing custom GUCs**.

The signed context does not claim to protect against:
- compromise of the trusted Rust application process or Context Issuer;
- misuse of a legitimate context already issued to that process;
- PostgreSQL superuser or host compromise;
- SQL injection changing data within the identity scope already authorized by the current token.

Parameterized SQL, least-privilege roles, SECURITY DEFINER hardening, worker separation and input validation remain mandatory. Signed context is not a replacement for those controls.

## 2. Exact SQL consumer map

The canonical clean schema contains 25 direct identity-GUC read/write expressions (source line numbers below refer to the baseline blob above).

| GUC | SQL location | Current security decision / effect |
|---|---|---|
| `app.tenant_id` | 1319–1320, dynamic `tenant_isolation` policy | Tenant predicate and write check for every table in the generated tenant-owned table set |
| `app.tenant_id` | 1343, 1348 | Tenant predicate and write check for `memories` |
| `app.caller_id` | 1345, 1350 | Episodic-memory ownership predicate in `memories` |
| `app.tenant_id` | 1356, 1365 | Tenant predicates for `memory_embeddings` |
| `app.tenant_id` | 1376, 1391 | Tenant predicates for `memory_conflicts` |
| `app.tenant_id` | 1412 | `tenants` runtime SELECT policy |
| `app.tenant_id` | 1416 | `principals` runtime SELECT policy |
| `app.tenant_id` | 1421–1424 | Tenant visibility and mutation policy for `kill_switches` |
| `app.tenant_id` | 1434–1435 | Runtime policy for `outbox_publication_receipts` |
| `app.tenant_id`, `app.principal_id` | 1594–1595 | `grant_caller_delegation`: chooses the Principal/tenant whose authority the function applies |
| `app.tenant_id`, `app.principal_id` | 1629–1630 | `revoke_caller_delegation`: chooses the Principal/tenant allowed to revoke |
| `app.tenant_id`, `app.principal_id` | 1658–1659 | `resolve_delegated_caller`: chooses the Principal/tenant whose active Caller grant is resolved and locked |
| `app.caller_id` write | 1682 | `resolve_delegated_caller` sets the effective episodic-memory Caller transaction-locally after resolving the grant |
| `app.tenant_id` | 1694 | `resolve_object_tenant` refuses lookup unless the supplied tenant matches the caller-writable tenant GUC |
| `app.tenant_id` | 1757 | `sweep_stale_invocation_deliveries` scopes the tenant-specific replay sweep |

The schema has no SQL writer for `app.tenant_id` or `app.principal_id`; those values are installed by the Rust transaction wrapper. The SQL function `resolve_delegated_caller` is the identified SQL writer for `app.caller_id`.

## 3. Rust transaction bootstrap — merged application-side migration

The Rust side is no longer a Draft branch. Rust PR #93 was merged into `qembed-object-runtime/main` (merge commit `1534c3c479289dcf5a642088761f86e5656d5ae3`). The production repository path now uses the signed transaction context:

1. `PgContext` owns the pool and `ContextIssuer`; trusted composition code opens transactions with `begin_principal(scope)` or `begin_caller(scope, caller_id)`.
2. The issuer binds the token to the PostgreSQL backend, transaction, database/deployment and signed claims, then installs the single transaction-local `app.context_token` envelope.
3. Object/Snapshot repository operations require Principal context; Caller-scoped operations require an explicitly resolved and validated Caller. Caller identity is not accepted from an external DTO.
4. Owner pre-authentication uses the narrow `owner_principals` / `owner_credentials` lookup and does not install `app.tenant_id` as a legacy identity fallback.

`begin_tenant_transaction` remains exported only for compatibility/tests; current production source has no caller of it. The Rust CI and PostgreSQL integration suite passed on the merged implementation. This closes the Rust-entry-point portion of QSA-003, but **does not** close the SQL portion: the canonical clean-install schema still contains legacy `app.tenant_id`, `app.principal_id` and `app.caller_id` RLS/function consumers. Deploying the new Rust runtime against that legacy SQL schema is not supported; the paired SQL signed-context migration must land first.

## 4. Executable current-risk regression

`tests/26_qsa003_legacy_guc_boundary.sql` is intentionally an exploit-demonstration test, not a desired security property. It runs as `qembed_runtime` and asserts that:
- setting `app.tenant_id` from tenant A to tenant B makes tenant B's seeded object visible;
- setting `app.principal_id` to another Principal allows the runtime role to create a delegation as that Principal;
- setting `app.caller_id` directly switches episodic-memory visibility from Caller A to Caller B without going through the resolver.

The test is wired into `tests/run_smoke.sh` after the existing tenant, delegation and Caller-memory fixtures. SQL PR #70 workflow [#45050613826](https://github.com/qembed/qembed-sql/actions/runs/45050613826) passed the full PostgreSQL 19 / pgvector 0.8.7 smoke suite: **442/442**. Its expected pass means the known weakness is reproduced and documented. After remediation, this test must be inverted into negative assertions: forged legacy GUC writes must have no effect on effective identity.

## 5. Required production migration

The selected direction is the qctx1 signed transaction context implemented as a PostgreSQL verifier + Rust ContextIssuer contract. The production migration must complete all of the following:

1. Replace every authorization/RLS read in section 2 with typed accessors derived only from `verified_context(app.context_token)`; preserve the uncorrelated scalar-subquery / InitPlan pattern so signature verification is statement-scoped, not per row.
2. Remove `app.caller_id` as an authorization input and remove the SQL resolver's `set_config('app.caller_id', ...)` side effect.
3. Redesign the pre-token delegation resolver used by ContextIssuer to accept the trusted tenant and Principal identifiers as explicit bound arguments, validate the exact active delegation and lock Principal/Caller/delegation rows, but never install an authorization GUC. The resolver result is used by the trusted Rust issuer to form the signed Caller claim; it is not an RLS identity source.
4. Convert `grant_caller_delegation` and `revoke_caller_delegation` to use verified token claims. Do not leave a legacy-GUC fallback.
5. Migrate every Rust repository transaction entry point from legacy `begin_tenant_transaction` to a signed-context transaction supplied with trusted Scope, selected Caller and ContextIssuer. Keep a separate explicit bootstrap-only transaction API only if its privileges and non-data-access use are demonstrated and reviewed.
6. Prove commit, rollback, savepoint, transaction restart, connection-pool reuse, same-backend replay and cross-backend replay behavior using the real Rust ContextIssuer and PostgreSQL 19 verifier.
7. Run negative tests as the actual `qembed_runtime` identity: forged tenant/Principal/Caller GUCs do not alter effective identity; modified/expired/wrong-binding tokens fail; runtime cannot read/change verification keys or mint signatures; worker discovery remains unavailable.
8. Package and review the native verifier, run independent security review and fuzzing, define ABI/build provenance and supported PostgreSQL versions, and benchmark representative RLS policies before production rollout.

## 6. Current status

- Source-level consumer map: completed in this PR.
- Current-risk negative-boundary demonstration: passed SQL PR #70 PostgreSQL 19 / pgvector 0.8.7 workflow #45050465672 (442/442).
- Signed-context direction: selected and accepted as the remediation architecture.
- SQL verifier + lifecycle feasibility prototype: SQL PR #69, still Draft and not production-approved; exact current-head PostgreSQL 19 verifier and smoke workflows passed.
- Rust ContextIssuer/PostgreSQL integration: Rust PR #93 merged; production repository entry points now use signed context.
- Canonical SQL RLS/function migration and removal of legacy GUC authorization reads: not implemented. This is the remaining code-level blocker for QSA-003.
- Independent review, fuzzing, packaging/provenance, supported PostgreSQL matrix, representative workload benchmark and deployment evidence: pending.

**QSA-003 remains `IN_PROGRESS`, not `VERIFIED`.** A green smoke run for the exploit-demonstration test only confirms that the current weakness is reproducible. Closure requires the inverted negative assertions and all production migration/release gates above.
