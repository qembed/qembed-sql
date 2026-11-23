# QSA-003 — signed-context SQL consumer migration

**Status:** Draft migration candidate; not production-approved and not a QSA-003 closure. It has been applied to the canonical clean-install schema in PostgreSQL 19 and exercised by the merged Rust ContextIssuer integration test (Rust PR #118). It remains a Draft candidate and is not production-approved.

## Purpose

`migrations/rt050_signed_context_rls.sql` replaces the remaining authorization reads of
`app.tenant_id`, `app.principal_id`, and `app.caller_id` in the canonical schema's
RLS policies and tenant/delegation SECURITY DEFINER functions.

All effective identity now comes from the verified qctx1 token through:

- `qembed_crypto.current_tenant_id()`
- `qembed_crypto.current_principal_id()`
- `qembed_crypto.current_caller_id()`

The RLS expressions use uncorrelated scalar subqueries so PostgreSQL can evaluate
the signed context as an InitPlan rather than re-verifying it for each row.

## Required installation order

This migration is intentionally separate from the clean-install schema. It has a
hard preflight and refuses to run until all four verifier functions exist:

1. Install the `qembed_context_verify` PostgreSQL extension built from the
   companion source in SQL PR #73.
2. Install the verification-key registry and the production `verified_context(text)`
   implementation, including the key lifecycle and role separation.
3. Install the typed `current_*_id()` accessors.
4. Apply the canonical clean-install schema at the same revision as this migration.
5. Apply `rt050_signed_context_rls.sql`.
6. Deploy the Rust ContextIssuer and signed repository entry points already merged in Rust PR #93 before sending tenant traffic through the migrated schema.

The verifier fixture in the PR stack is still a feasibility harness. It is not
itself the production key-registry deployment or an operator runbook.

## Behavior changes

- Every generic tenant-owned RLS policy reads tenant identity from the signed token.
- Semantic memories remain tenant-scoped.
- Episodic memories require both the signed tenant and signed Caller. A token with
  `caller_id: null` sees no Caller-scoped rows.
- Memory embeddings and conflicts continue to inherit visibility from the parent
  memory and also require the signed tenant.
- Tenant, Principal, kill-switch and outbox-receipt policies use signed tenant identity.
- Delegation grant/revoke functions use signed tenant and Principal claims.
- The pre-token Caller resolver now accepts explicit tenant, Principal and Caller
  UUID arguments, locks the active delegation/lifecycle rows, and returns the
  resolved identity to the trusted Rust issuer. It does not write `app.caller_id`
  or any other identity GUC.
- Object-tenant resolution and stale invocation-delivery recovery use the signed
  tenant accessor.

## Compatibility and rollout warning

This migration is deliberately incompatible with legacy repository transactions
that call only `begin_tenant_transaction`: without a signed `app.context_token`,
the new policies fail closed and return no tenant rows. Do not apply it to a live
deployment until all repository transaction entry points use the signed-context
API and the matching ContextIssuer is deployed.

Current Rust `main` no longer uses the legacy GUC transaction bootstrap on production repository paths. `begin_tenant_transaction` remains only as a compatibility/test helper. Once this SQL migration is applied, the old GUCs must have no authorization effect. The Rust PR #118 runs the actual Rust ContextIssuer against this exact canonical migration candidate; the CI test also verifies tenant/Principal/Caller behavior through the SQL verifier. This is integration evidence for the candidate, not a production rollout approval.

## Validation gates still required

- Apply this migration to the canonical schema in PostgreSQL 19 with the real
  verifier extension and staged/active test key.
- [x] Exercise the prototype through the actual Rust ContextIssuer for both Caller-scoped and
  Principal-only tokens (Rust PR #93 merged).
- [x] Run the actual Rust ContextIssuer against the canonical clean-install SQL schema and this migration (Rust PR #118; SQL candidate commit `ae823fc1b328c4c1a2a33bf3fef7721ca6fca27e`).
- As `qembed_runtime`, prove tenant/Principal/Caller GUC forgery cannot alter
  RLS visibility or delegation authority.
- [x] Verify commit, rollback, savepoint, pool reuse, expiry, same-backend replay and
  cross-backend replay behavior against the prototype fixture (Rust PR #93).
- [x] Repeat token commit/rollback, pool/backend binding and replay checks against the canonical SQL migration in Rust PR #118.
- Run the full SQL and Rust integration suites and inspect RLS query plans.
- Complete extension packaging/provenance, fuzzing, independent security review,
  supported PostgreSQL matrix and workload benchmark.

**QSA-003 remains IN_PROGRESS until these gates pass on merged code.**
