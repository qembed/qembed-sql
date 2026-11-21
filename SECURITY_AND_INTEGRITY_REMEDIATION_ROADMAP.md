# QEmbed-SQL Security & Integrity Remediation Roadmap

**Priority:** P0 — BLOCKER  
**Status:** Active; audit findings require revalidation against current `master`  
**Scope:** `qembed/qembed-sql` only, unless a separately approved architecture decision explicitly expands scope  
**Audit baseline:** `164da3c` (user-run adversarial audit; PostgreSQL 16.15 + pgvector 0.8.7)  
**Roadmap branch base:** `495602a20a0bfb25873da856e2537c1a35da0d40`  
**Validation target:** PostgreSQL 19 + pgvector 0.8.7  
**Rule:** No finding is closed by documentation, code inspection alone, or a green legacy smoke suite. Closure requires a regression test that fails before the fix and passes after it, plus recorded validation evidence.

---

## 0. Operating rules

This roadmap supersedes the ordinary SQL feature backlog while any P0 item is open.

1. **P0 freeze:** do not start unrelated SQL features until all P0 items below are closed or explicitly accepted through a documented threat-model decision by the project owner.
2. **Revalidate first:** the supplied audit was run against commit `164da3c`; the audit baseline `164da3c` is not current `master`; current remediation base is `04d86be8a771c6e24f05379ac415216ac6467916`. Every finding starts as `REVALIDATE`, not as an assertion that the current HEAD still contains the defect.
3. **One security boundary per PR:** prefer small, independently reviewable PRs. Do not combine unrelated role, RLS, trigger, retention, or dependency changes.
4. **Negative tests are mandatory:** tests must prove that the forbidden operation fails or reveals no data, not merely that the intended operation succeeds.
5. **Test with the real application role:** tests run as superuser or schema owner do not prove runtime-role isolation. Include role switching and realistic grants.
6. **Target environment:** PostgreSQL 19 + pgvector 0.8.7. PostgreSQL 16 results from the original audit remain useful reproduction evidence, but are not final target validation.
7. **No silent contract changes:** preserve existing Rust physical contracts. Any required Rust change must be proposed separately with an explicit architecture decision; do not smuggle it into a SQL remediation.
8. **Evidence per item:** record exact commit, test file/command, database version, pgvector version, result, and relevant CI run/PR.
9. **No blanket closure:** a passing full suite does not close a finding unless its dedicated regression assertion is present and exercised.
10. **Re-audit after fixes:** after P0 remediation, rerun the adversarial scenarios independently against the merged commit.

### Status vocabulary

- `REVALIDATE` — reported by the audit; must be checked against current `master`.
- `SOURCE_CONFIRMED` — current source/catalog assertions still expose the reported path; a current-base live database reproduction is pending.
- `CONFIRMED` — reproduced against the current baseline database, with evidence recorded below.
- `NOT_REPRODUCED` — current DDL/behavior already enforces the reported invariant; regression evidence is recorded.
- `DEFERRED_TO_FUTURE_FEATURE` — the schema contract is explicitly future-facing and no current runtime path claims support.
- `DEFERRED_TO_RUST` — the SQL concern is governed by an accepted Rust/application contract and requires its application-level tests.
- `DOCUMENTED_RISK` — the current trust boundary is explicit, but owner approval is still required to accept it or fund a stronger architecture.
- `IN_PROGRESS` — remediation PR is open.
- `BLOCKED` — requires a documented decision or external dependency.
- `VERIFIED` — regression test and target-environment evidence pass on merged code.
- `ACCEPTED_RISK` — explicitly accepted by the project owner with rationale and threat-model boundary.

---

## 1. P0 — security boundary and data-integrity findings

These items are the first execution wave. The audit classified the original observations as Medium, but the project-level remediation program is P0 because they concern cross-tenant disclosure, privilege boundaries, bypassable invariants, and loss of durable work.

### QSA-001 — Separate tenant runtime permissions from cross-tenant worker discovery

**Reported severity:** Medium  
**Original evidence:** reproduced on `164da3c`  
**Current status:** `VERIFIED` — merged in [PR #29](https://github.com/qembed/qembed-sql/pull/29), commit `61c37cf83814a109268f3b02d812f6f67018c5a0`. PostgreSQL 19 / pgvector 0.8.7 smoke suite passed 396/396 on the PR head and again post-merge.

**Implementation:** `qembed_worker` is a NOLOGIN, NOSUPERUSER, NOBYPASSRLS role with only the three cross-tenant maintenance entry points. `qembed_runtime` no longer has EXECUTE on them; the tenant-scoped invocation recovery function remains runtime-accessible.

**Rollout prerequisite:** provision a separate LOGIN identity for background workers and grant it membership in `qembed_worker`. Never grant `qembed_worker` to the tenant runtime login.

**Reported behavior:** the tenant-facing `qembed_runtime` role could execute cross-tenant discovery functions, including:
- `list_expired_invocation_leases`
- `list_pending_reconciliations`
- `sweep_expired_reservations`

The first two can return identifiers belonging to other tenants. Background-worker discovery must not be available to an ordinary tenant request role.

**Required work**
- [x] Inspect current function ownership, SECURITY DEFINER status, EXECUTE grants, role memberships, and all transitive call paths.
- [x] Define the minimum role model for tenant request execution versus cross-tenant worker execution. Evaluate a dedicated `qembed_worker` role; do not assume the role name alone is sufficient.
- [x] Revoke cross-tenant discovery/sweeper execution from `qembed_runtime`.
- [x] Grant only the required functions to the worker role; ensure the worker role cannot inherit broad administrative or schema-owner privileges.
- [x] Add catalog assertions for the exact EXECUTE matrix and role membership.
- [x] Add negative tests proving `qembed_runtime` cannot call these functions and positive tests proving the intended worker can.
- [x] Verify returned rows are limited to the worker contract and cannot be used to read tenant payloads.

**Deployment follow-up (not part of the clean-install schema):** [ ] provision a dedicated LOGIN identity for background workers and grant it membership in `qembed_worker`; [ ] verify the tenant runtime LOGIN is not a member of `qembed_worker`.

**Acceptance:** runtime role cannot enumerate another tenant's identifiers through worker functions; only the explicitly authorized worker role can perform the required cross-tenant discovery.

### QSA-002 — Harden every SECURITY DEFINER function against temporary-object shadowing

**Reported severity:** Medium  
**Original evidence:** reproduced on `164da3c`  
**Current status:** `VERIFIED` — merged in [PR #28](https://github.com/qembed/qembed-sql/pull/28), commit `7cad9084e3fc74012eaf73d90a17adc8ded4a736`. PostgreSQL 19 / pgvector 0.8.7 smoke suite passed 388/388 on the PR head and again post-merge.

**Implementation:** all 11 SECURITY DEFINER functions are catalog-checked for `pg_temp` last; the event allocator, embedding dimension guard, and published-pointer guard are pinned. Regression tests attempt temporary relation shadowing for all three reported attack paths.

**Reported behavior:** `assign_event_stream_version` lacked `pg_temp` in its pinned `search_path`. A caller-created temporary relation could shadow a trusted relation and influence the function. The audit also reported exploit paths affecting `check_embedding_dim` and `object_published_pointer_guard`.

**Required work**
- [x] Enumerate every SECURITY DEFINER function from PostgreSQL catalogs on a clean install.
- [x] Verify a fixed search path for each function, with `pg_temp` explicitly last (after trusted schemas).
- [x] Correct every missing or incorrectly ordered path; do not rely on README assertions.
- [x] Revoke database TEMP privilege from PUBLIC and application roles where compatible with the deployment model; document any role that legitimately requires TEMP.
- [x] Extend `tests/22_definer_security.sql` to assert search_path for every SECURITY DEFINER function, not a hand-maintained subset.
- [x] Add adversarial temporary-table shadowing tests for stream version allocation, embedding dimension validation, published-pointer validation, and every other definer function that resolves relations.
- [x] Prove the attack fails under the actual runtime role.

**Defense-in-depth follow-up:** [ ] evaluate revoking database TEMP from PUBLIC/application roles after auditing every runtime workflow that legitimately creates temporary objects. This is separate from the verified search_path fix.

**Acceptance:** no covered function resolves an attacker-controlled temporary relation in place of a trusted object; catalog tests fail if a new SECURITY DEFINER function omits the required path.

### QSA-003 — Document and bound the trust model for session GUC identity

**Reported severity:** Medium  
**Original evidence:** reproduced on `164da3c`  
**Current status:** `DOCUMENTED_RISK` / architecture decision required — [ADR RT-049](ADR_RT-049_Principal_Caller_Delegation.md) now explicitly states that `app.tenant_id`, `app.principal_id`, and `app.caller_id` are session-settable and can be forged by arbitrary SQL under `qembed_runtime`. This documents the boundary; it does not mitigate it.

**Reported behavior:** `app.tenant_id`, `app.principal_id`, and `app.caller_id` are session settings writable by the runtime role. Under arbitrary SQL execution as `qembed_runtime`, a caller can forge context and bypass the intended delegation boundary, including episodic-memory isolation.

**Required work**
- [ ] Map every identity/security decision derived from these GUCs and every function that sets or consumes them.
- [ ] State explicitly whether arbitrary SQL execution under `qembed_runtime` is inside or outside the database threat model.
- [ ] Record the consequences: RLS driven by caller-writable GUCs is tenant isolation against application mistakes, not an independent boundary against SQL execution as that role.
- [ ] Evaluate mitigations that do not silently change the Rust transaction contract (for example, narrower database roles or a trusted context-establishment boundary).
- [ ] Add tests that demonstrate the current boundary and prevent documentation from claiming stronger isolation than is actually provided.
- [ ] Obtain an explicit owner decision: remediation design or `ACCEPTED_RISK` with rationale.

**Acceptance:** the threat model is explicit, technically accurate, and approved. This item cannot be closed merely by adding prose while product/security claims still imply GUCs are unforgeable.

### QSA-004 — Remove caller-controlled bypass of knowledge interval guards

**Reported severity:** Medium  
**Original evidence:** reproduced on `164da3c`  
**Current status:** `VERIFIED` — merged in [PR #34](https://github.com/qembed/qembed-sql/pull/34), commit `5490d855f9ef9a97d255987747ceb6e0c75f6062`. PostgreSQL 19 / pgvector 0.8.7 smoke suite passed 409/409 on the PR head and again post-merge.

**Implementation:** the GUC is no longer an authorization signal. `knowledge_documents_sync()` runs as a narrowly privileged SECURITY DEFINER trigger owner; only interval-column UPDATE and predicate-column SELECT are granted on `knowledge_chunks`. Runtime cannot forge authority by setting the old GUC.

**Reported behavior:** a runtime role with UPDATE on `knowledge_chunks` could set `qembed.interval_sync = 'on'` and modify validity intervals directly, bypassing the intended document-revision synchronization guard.

**Required work**
- [ ] Trace all reads/writes of `qembed.interval_sync` and identify the intended trusted synchronization path.
- [ ] Replace caller-controlled authorization-by-GUC with a boundary that an ordinary runtime caller cannot forge, or narrow table/function privileges so the caller cannot perform the guarded update directly.
- [ ] Preserve the legitimate `knowledge_documents_sync` behavior.
- [ ] Add a negative test for direct interval mutation after setting the GUC as `qembed_runtime`.
- [ ] Add a positive test proving the approved document revision path still synchronizes intervals atomically.

**Acceptance:** runtime SQL cannot self-authorize interval changes; the approved document update path remains functional.

### QSA-005 — Make Caller revocation irreversible

**Reported severity:** Medium  
**Original evidence:** reproduced on `164da3c`  
**Current status:** `VERIFIED` — merged in [PR #31](https://github.com/qembed/qembed-sql/pull/31), commit `67217d7f14cb197a7bbc8901eea0811de84a5c29`. PostgreSQL 19 / pgvector 0.8.7 smoke suite passed 404/404 on the PR head and again post-merge.

**Implementation:** Caller identity fields are immutable; once revoked, `revoked_at` cannot be cleared or rewritten. Runtime-role negative tests prove reactivation and token-identity rewrites are rejected.

**Reported behavior:** unlike owner credentials and delegation records, a Caller revocation could be reversed by setting `callers.revoked_at` back to NULL.

**Required work**
- [ ] Inspect current Caller lifecycle triggers, grants, and all write paths.
- [ ] Define whether revocation is final. The supplied audit assumes final revocation, consistent with the existing delegation/credential model.
- [ ] Enforce immutable revocation at the database boundary.
- [ ] Ensure reactivation, if a product requirement exists, uses a new identity/history record rather than erasing revocation history.
- [ ] Add negative tests for clearing or rewriting `revoked_at` and positive tests for the approved lifecycle.

**Acceptance:** a revoked Caller cannot be silently reactivated by the runtime or an ordinary update path.

### QSA-006 — Protect the platform kill switch from tenant deletion

**Reported severity:** Medium  
**Original evidence:** reproduced on `164da3c`  
**Current status:** `VERIFIED` — merged in [PR #35](https://github.com/qembed/qembed-sql/pull/35), commit `aee409469e72f897799623eedbd01c854fbb9c33`. PostgreSQL 19 / pgvector 0.8.7 smoke suite passed 416/416 on the PR head and again post-merge.

**Implementation:** each switch records immutable `managed_by_role` assigned from actual role membership. Runtime can manage its own switches but cannot disable/delete a tenant-scoped switch created by `qembed_admin`.

**Reported behavior:** policy `ks_write` appeared to allow the runtime role to delete a tenant's kill-switch row, while the `T-50` check constrained only the `platform` value.

**Required work**
- [ ] Re-check current RLS policies, table grants, role attributes, and all kill-switch mutation functions.
- [ ] Confirm intended ownership: can a tenant disable its own switch, or is the switch controlled exclusively by platform operations?
- [ ] If platform-owned, restrict insert/update/delete to the platform operations boundary and prevent tenant runtime deletion.
- [ ] If tenant deletion is intentional, document the precise semantics and prove it cannot disable a platform-enforced global stop.
- [ ] Add cross-role negative tests for tenant attempts to delete or weaken platform kill-switch state.

**Acceptance:** the kill-switch authority is explicit and a tenant cannot remove a control that is intended to be platform-enforced.

### QSA-007 — Preserve pending outbox replay during retention purge

**Reported severity:** Medium  
**Original evidence:** reproduced on `164da3c`  
**Current status:** `VERIFIED` — merged in [PR #30](https://github.com/qembed/qembed-sql/pull/30), commit `04d86be8a771c6e24f05379ac415216ac6467916`. PostgreSQL 19 / pgvector 0.8.7 smoke suite passed 400/400 on the PR head and again post-merge.

**Implementation:** retention now excludes rows with `replay_requested_at IS NOT NULL`; a dedicated regression test proves pending replay survives while an otherwise eligible delivered row is purged.

**Reported behavior:** `retention_purge('outbox_messages')` could delete rows that still had `replay_requested_at`, losing pending replay work.

**Required work**
- [x] Inspect current outbox replay constraints, retention function, and dispatcher/recovery semantics.
- [x] Ensure retention eligibility excludes every row with pending replay (including any additional replay/in-flight states in the current schema).
- [x] Add a regression test with an old, delivered outbox row that has a pending replay marker; purge must retain it.
- [x] Add a control test proving an old delivered row without pending replay remains purgeable.
- [x] Verify replay receipts and replay markers remain consistent after retention.

**Acceptance:** retention cannot delete an outbox row while replay is pending; ordinary eligible retention still works.

---

## 2. P1 — schema invariants, dependency gates, and correctness findings

These findings were inferred from DDL rather than reproduced in the original audit. They must be verified before implementation. They remain part of the P0 remediation program, but follow the direct security-boundary fixes unless revalidation reveals a more urgent impact.

### QSA-008 — Reconcile verified-memory principal foreign keys with the Rust auth model

**Reported severity:** Medium (inferred)  
**Current status:** `DEFERRED_TO_FUTURE_FEATURE` — the schema comment above `owner_principals` explicitly states that `principals`/`callers` are the future model and are not used by the current Rust auth path. The current Rust repository has no memory write adapter. This is not a demonstrated current-path failure; it must be reconciled before Verified memory is enabled through Rust.

- [ ] Trace `memories_verified_guard`, its FK targets, and every Rust/SQL write path for Principal identity.
- [ ] Determine whether `principals` and `owner_principals` intentionally represent distinct identities or whether this is a broken integration.
- [ ] Do not equate the tables or UUIDs by assumption.
- [ ] Add an end-to-end test for creating a Verified memory through the supported runtime path.

**Acceptance:** the supported write path can create a Verified memory with the intended principal identity, or the feature is explicitly blocked/documented until its architecture is approved.

### QSA-009 — Require a lease for Executing ToolExecution rows

**Reported severity:** Medium (inferred)  
**Current status:** `NOT_REPRODUCED` — current DDL already enforces the invariant through combined checks: `(status = 'Executing') = (lease_owner IS NOT NULL)` and `(lease_owner IS NULL) = (lease_until IS NULL)`. Together they imply `Executing => lease_until IS NOT NULL`. A direct runtime transition test was added in [PR #39](https://github.com/qembed/qembed-sql/pull/39), merged as `495602a20a0bfb25873da856e2537c1a35da0d40`; PostgreSQL 19 / pgvector 0.8.7 smoke passed 420/420 on PR head.

- [x] Inspect the current ToolExecution status/lease CHECK constraints and transition guard.
- [x] Add a negative transition test proving an Executing row cannot omit `lease_until`.
- [ ] Verify reconciliation discovery against the same constraint in an end-to-end worker test.

**Acceptance:** an Executing row is always discoverable by the lease/reconciliation logic and cannot exist in an unleased ambiguous state.

### QSA-010 — Make reservation sweeper robust against counter drift

**Reported severity:** Medium (inferred)  
**Current status:** `VERIFIED` — merged in [PR #42](https://github.com/qembed/qembed-sql/pull/42), commit `bd2dfc85c2b4f54d3bab088914a2da6c413a4069`. PostgreSQL 19 / pgvector 0.8.7 smoke suite passed 421/421 on the PR head and again post-merge.

**Chosen invariant:** reservation expiry uses saturating decrements (`GREATEST(0, current - reserved)`) for aggregate token and cost counters, matching the existing Caller counter behavior. This keeps one drifted counter from aborting the worker batch. It does not itself diagnose or persist the source of counter drift; anomaly accounting is a separate follow-up if required.

- [x] Inspect current `usage_counters` and `caller_usage_counters` release logic.
- [x] Choose and document saturating release semantics for counter drift.
- [x] Ensure one inconsistent counter cannot cause an unexpected batch-wide failure.
- [x] Add a regression test for underflow/drift; normal exact-balance release remains covered by the existing lifecycle tests.

**Acceptance:** reservation expiry has deterministic, tested behavior under counter drift and cannot create negative usage or abort the batch.

### QSA-011 — Enforce pgvector minimum version 0.8.7 including patch comparison

**Reported severity:** Medium (inferred)  
**Current status:** `VERIFIED` — merged in [PR #36](https://github.com/qembed/qembed-sql/pull/36), commit `dfc519e4d70a2d438ef0a4472caf1d6994097f9f`. PostgreSQL 19 / pgvector 0.8.7 smoke suite passed 418/418 on the PR head and again post-merge.

- [ ] Inspect the actual extension-version gate and CI matrix.
- [ ] Reject pgvector versions below 0.8.7, including earlier 0.8.x patch releases.
- [ ] Compare the full semantic version, not only major/minor.
- [ ] Add tests for 0.8.0, 0.8.6, 0.8.7, and a later compatible release.
- [ ] Ensure CI provisions the exact target version.

**Acceptance:** clean install refuses unsupported pgvector versions and accepts 0.8.7 or later according to the documented compatibility policy.

### QSA-012 — Decide whether snapshots.content_hash is database-verified

**Reported severity:** Medium (inferred)  
**Current status:** `DEFERRED_TO_RUST` / architecture decision required — accepted ADR RUST-044 treats SHA-256 as a lookup discriminator and requires exact canonical-byte comparison at the Rust deduplication boundary; it does not mandate a database digest-equality CHECK. Read-time detection of corrupted persisted hashes remains a Rust acceptance requirement to verify.

- [ ] Re-read `ADR_RUST-044_Identical_Content_Version_Deduplication.md` and the current Rust snapshot write/read contract.
- [ ] Determine whether the database must enforce `content_hash = SHA-256(canonical_json)` or whether Rust read-time verification is the approved boundary.
- [ ] Record the decision in the ADR and align this roadmap with it.
- [ ] If database enforcement is selected, add negative tests for mismatched hash/bytes and ensure the chosen digest implementation is available and deterministic.
- [ ] If application-level verification remains intentional, add explicit evidence and a test that corrupted persisted hashes are detected before use.

**Acceptance:** one documented source of truth for hash integrity exists; the DB and Rust layers do not make contradictory guarantees.

---

## 3. P2 — smaller hardening and privacy findings

Revalidate all items against current schema before changing code.

- [ ] **QSA-013 — Unreachable Invocation states:** determine whether `WaitingForInput` and `WaitingForApproval` are intentionally reserved or unreachable dead vocabulary; align constraints/domain docs.
- [ ] **QSA-014 — Duplicate trigger/function definition:** inspect duplicate `object_versions_guard` definitions; remove dead/ambiguous definition if confirmed and test the effective trigger binding.
- [ ] **QSA-015 — Fail-closed receipt policy:** check `outbox_publication_receipts` policy handling of empty-string GUCs; use explicit fail-closed parsing where required and add tests for unset, empty, malformed, and valid context.
- [ ] **QSA-016 — Hash/token length constraints:** assess and add appropriate length CHECKs for `payload_hash`, `callers.token_hash`, and `principals.key_hash`, without changing valid Rust encodings.
- [ ] **QSA-017 — Cross-tenant uniqueness side channels:** assess global UNIQUE constraints on `object_id`, `snapshot_id`, and `event_id`; prefer tenant-scoped uniqueness where compatible with all FKs and contracts. Test that foreign-tenant UUID collisions do not expose unintended existence information.
- [ ] **QSA-018 — TRUNCATE defense:** verify privileges and add explicit TRUNCATE protections for append-only `events` and `outbox_publication_receipts` if a role can otherwise truncate them.

---

## 4. P2 — performance follow-up (measure before optimizing)

These were catalog-based observations, not measured regressions. Capture query plans and representative row counts before adding indexes.

- [ ] **QSA-019 — Knowledge document synchronization index:** evaluate `knowledge_chunks (tenant_id, object_id, document_id)` for `knowledge_documents_sync` and cascading deletes.
- [ ] **QSA-020 — Memory child FK indexes:** evaluate indexes supporting FKs/cascades for `memory_embeddings` and `memory_conflicts`.
- [ ] **QSA-021 — Knowledge embedding FK index:** evaluate FK-supporting indexes for `knowledge_chunk_embeddings`.
- [ ] **QSA-022 — Invocation delivery sweep expression index:** measure `payload->>'invocation_id'` lookup in `sweep_stale_invocation_deliveries`; add an expression index only if the plan and workload justify it.
- [ ] **QSA-023 — Duplicate event ordering index:** verify whether `events_aggregate_order_idx` duplicates `events_stream_version_unique`; remove redundancy only after checking uniqueness and query-plan requirements.

**Acceptance for performance items:** before/after plans and representative measurements are attached to the PR. No index is added or removed solely from catalog speculation.

---

## 5. Execution order

1. [ ] **Wave A — Revalidation baseline:** inspect current `04d86be8a771c6e24f05379ac415216ac6467916` schema, role grants, RLS policies, SECURITY DEFINER functions, and tests; mark each finding `CONFIRMED`, `NOT_REPRODUCED`, or `BLOCKED` with evidence.
2. [ ] **Wave B — P0 security:** QSA-001 through QSA-006. Prioritize role separation and SECURITY DEFINER hardening; resolve the GUC threat-model decision before claiming tenant isolation against arbitrary SQL.
3. [ ] **Wave C — P0 data integrity:** QSA-007.
4. [ ] **Wave D — P1 invariants:** QSA-008 through QSA-012.
5. [ ] **Wave E — P2 hardening:** QSA-013 through QSA-018.
6. [ ] **Wave F — measured performance:** QSA-019 through QSA-023.
7. [ ] **Wave G — independent adversarial retest:** rerun every reproduced exploit and all new negative tests on PostgreSQL 19 + pgvector 0.8.7 against the final merged `master`.

A wave may proceed in parallel only when its changes do not depend on an unresolved security/contract decision. Do not batch all findings into one PR.

---

## 6. Mandatory PR and validation checklist

Every remediation PR must include:

- [ ] Exact QSA IDs addressed and IDs explicitly out of scope.
- [ ] Revalidation result against the PR base commit.
- [ ] The exploit/regression test that demonstrates the pre-fix failure.
- [ ] Negative test as `qembed_runtime` and any other relevant least-privilege role.
- [ ] Positive test proving the intended trusted workflow still works.
- [ ] Catalog assertions for grants, role membership, policies, trigger bindings, or function configuration where relevant.
- [ ] Full smoke suite on PostgreSQL 19 + pgvector 0.8.7.
- [ ] Exact PR-head CI checks green before merge.
- [ ] Post-merge CI green on the resulting `master` commit.
- [ ] Evidence recorded in the relevant QSA item below.

**Do not merge** if a security test is skipped, run only as superuser, or does not exercise the actual runtime/worker role boundary.

---

## 7. Evidence log

| QSA | Baseline revalidation | PR / commit | PG19 + pgvector 0.8.7 | Status |
|---|---|---|---|---|
| QSA-001 | PR #29; 396/396 PR-head and post-merge | [PR #29](https://github.com/qembed/qembed-sql/pull/29) | 396/396 | VERIFIED |
| QSA-002 | PR #28; 388/388 PR-head and post-merge | [PR #28](https://github.com/qembed/qembed-sql/pull/28) | 388/388 | VERIFIED |
| QSA-003 | Explicit GUC spoofing threat model in ADR RT-049; owner decision pending | [ADR RT-049](ADR_RT-049_Principal_Caller_Delegation.md) | Pending | DOCUMENTED_RISK |
| QSA-004 | PR #34; 409/409 PR-head and post-merge | [PR #34](https://github.com/qembed/qembed-sql/pull/34) | 409/409 | VERIFIED |
| QSA-005 | PR #31; 404/404 PR-head and post-merge | [PR #31](https://github.com/qembed/qembed-sql/pull/31) | 404/404 | VERIFIED |
| QSA-006 | PR #35; 416/416 PR-head and post-merge | [PR #35](https://github.com/qembed/qembed-sql/pull/35) | 416/416 | VERIFIED |
| QSA-007 | PR #30; 400/400 PR-head and post-merge | [PR #30](https://github.com/qembed/qembed-sql/pull/30) | 400/400 | VERIFIED |
| QSA-008 | Future principal/memory model; no current Rust memory write adapter | — | N/A | DEFERRED_TO_FUTURE_FEATURE |
| QSA-009 | Combined CHECK constraints; runtime negative test PR #39; 420/420 | [PR #39](https://github.com/qembed/qembed-sql/pull/39) | 420/420 | NOT_REPRODUCED |
| QSA-010 | PR #42; 421/421 PR-head and post-merge | [PR #42](https://github.com/qembed/qembed-sql/pull/42) | 421/421 | VERIFIED |
| QSA-011 | PR #36; 418/418 PR-head and post-merge | [PR #36](https://github.com/qembed/qembed-sql/pull/36) | 418/418 | VERIFIED |
| QSA-012 | ADR RUST-044 assigns exact-byte dedup check to Rust; read-time corruption test pending | — | Pending | DEFERRED_TO_RUST |
| QSA-013–018 | Pending | — | Pending | REVALIDATE |
| QSA-019–023 | Pending | — | Pending | REVALIDATE |

---

## 8. Audit provenance and limitations

The initial findings were supplied from an adversarial audit of commit `164da3c` on PostgreSQL 16.15 + pgvector 0.8.7:

- QSA-001 through QSA-007 were reported as reproduced against a live database.
- QSA-008 through QSA-012 were inferred from DDL and were not reported as reproduced.
- QSA-013 through QSA-018 were reported as minor observations.
- QSA-019 through QSA-023 were catalog-based performance observations, not measured.

The current repository base for this roadmap is `495602a20a0bfb25873da856e2537c1a35da0d40`. QSA-001, QSA-002, and QSA-007 have since been remediated and independently re-run through the PostgreSQL 19 / pgvector 0.8.7 smoke workflow. Remaining findings still require revalidation against this exact base before remediation. The supplied audit is evidence and a prioritized test plan, not a substitute for inspecting current source and behavior.

This roadmap records the remediation program; it does not itself certify the schema as secure or production-ready.
