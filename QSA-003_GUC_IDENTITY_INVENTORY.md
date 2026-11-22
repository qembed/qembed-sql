# QSA-003 — identity GUC source inventory and executable boundary evidence

**Baseline:** `master` at `4ed801018698c17d6e5ff2f5153a9a3e034ff681`  
**Status:** audit evidence only; this document does not remediate the trust boundary.

## Finding

The settings `app.tenant_id`, `app.principal_id`, and `app.caller_id` are ordinary PostgreSQL custom settings. `SET LOCAL` / `set_config(..., true)` controls transaction lifetime, not who is allowed to choose the value. A session executing as `qembed_runtime` can set them directly.

Therefore the current RLS and SECURITY DEFINER design protects against absent scope and application mistakes when the trusted Rust transaction wrapper supplies identity correctly. It does not protect against arbitrary SQL execution under `qembed_runtime`. Do not describe the GUCs as authenticated, unforgeable, or as an independent defense against SQL injection.

## Current source inventory

The clean-install schema consumes identity settings in these places:

| Setting | Consumer | Purpose |
|---|---|---|
| `app.tenant_id` | Generic tenant RLS policy loop (schema around line 1319) | Tenant boundary for tenant-owned relations, including objects, versions, callers, invocations, idempotency, interaction, knowledge, tools, events/outbox, budgets/reservations, usage counters, and related lifecycle tables |
| `app.tenant_id` | RLS on `memories`, `memory_embeddings`, `memory_conflicts` (around lines 1343–1391) | Tenant boundary for memory rows and their dependent rows |
| `app.tenant_id` | RLS on `tenants`, `principals`, `kill_switches`, `outbox_publication_receipts` (around lines 1412–1435) | Tenant-scoped reads/writes on restricted-global and receipt relations |
| `app.principal_id` + `app.tenant_id` | `grant_caller_delegation` (around line 1594) | Chooses the Principal allowed to create a direct delegation |
| `app.principal_id` + `app.tenant_id` | `revoke_caller_delegation` (around line 1629) | Chooses the Principal allowed to revoke its own delegation |
| `app.principal_id` + `app.tenant_id` | `resolve_delegated_caller` (around line 1658) | Resolves and locks the active Principal/Caller/delegation tuple |
| `app.caller_id` | RLS on `memories` (around lines 1343–1350) | Restricts episodic memories to the selected Caller |
| `app.caller_id` | `resolve_delegated_caller` (around line 1682) | Installs the selected Caller after checking the active delegation |
| `app.tenant_id` | `resolve_object_tenant` (around line 1694) | Prevents resolving an object outside the supplied current tenant context |
| `app.tenant_id` | `invocation_replay_sweeper` (around line 1757) | Scopes replay work to the current tenant |

The schema itself does not establish `app.tenant_id` or `app.principal_id` from authenticated credentials. That establishment currently belongs to the Rust transaction/authentication path. The only schema-side write to an identity GUC is the transaction-local `app.caller_id` assignment in `resolve_delegated_caller`.

## Existing and added executable evidence

- `tests/17_tenant_rls.sql`: runs as `qembed_runtime`; it already demonstrates that changing `app.tenant_id` from Tenant A to Tenant B changes the rows visible through RLS. QSA-003 adds an explicitly named assertion for that trust-boundary behavior.
- `tests/07_principal_caller_delegation.sql`: QSA-003 adds a demonstration that changing `app.principal_id` to another active Principal allows the runtime session to exercise that Principal's delegation authority.
- `tests/24_caller_memory_rls.sql`: QSA-003 adds a demonstration that directly setting `app.caller_id` to another active Caller changes which episodic memories are visible.

These are deliberately **risk-demonstration** assertions, not claims that the behavior is secure. They must be replaced by negative spoofing tests when a verified-context implementation is adopted.

## Security consequences and boundary

If an attacker can execute arbitrary SQL as `qembed_runtime`, that attacker can forge the tenant, Principal, and Caller context consumed by RLS and delegation functions. The practical consequences include cross-tenant row visibility and bypass of the intended Caller-scoped episodic-memory boundary. A transaction-local setting does not prevent this.

Until a stronger context mechanism is implemented and verified:
- database credentials and the runtime connection path must remain application-internal;
- all SQL must use bound parameters;
- user-supplied SQL and dynamic SQL assembled from untrusted input are prohibited;
- RLS is a defense against missing scope and application bugs, not an independent boundary against SQL execution under the runtime role.

## Remediation direction

The parked RT-050 design proposes one signed context token bound to the exact PostgreSQL backend PID and transaction ID. A trusted issuer authenticates the Principal, validates the exact selected Caller delegation, and signs the claims; PostgreSQL verifies the signature using public verification material. Raw identity GUCs must cease to be authorization inputs. The verifier must not mint tokens or expose signing capability to `qembed_runtime`.

This direction remains a proposal until a PostgreSQL 19 prototype proves:
1. a vetted signature-verification mechanism is available and supportable on the target deployment;
2. token binding to backend PID and transaction ID is correct, including retries and transaction-ID assignment;
3. altered, expired, wrong-key, wrong-issuer/audience, wrong-backend, wrong-transaction, and Caller-substitution tokens fail closed;
4. context cannot survive commit, rollback, error, savepoint handling, or pooled-connection reuse;
5. delegation revocation locking and Principal/Caller lifecycle semantics remain intact.

No production schema or Rust transaction contract is changed by this audit-evidence change.
