# RT-049 — Principal-to-Caller delegation

**Status:** accepted architecture / SQL contract introduced by SQL-011  
**Scope:** SQL schema and SQL tests; Rust integration follows in the Object Runtime repository.

## Decision

Authentication identity (owner_principals) and invocation identity (callers) remain separate entities. A verified tenant-owner Principal may explicitly act as one or more tenant-local Callers. The selected Caller, not the Principal, is persisted as object_invocations.caller_id and scopes caller-owned idempotency and interaction history.

The relationship is represented by principal_caller_delegations. UUID equality between owner_principals.caller_id and callers.id has no semantic meaning and is never used as an implicit mapping.

## Invariants

1. Every delegation is tenant-scoped and has composite foreign keys to both owner_principals(tenant_id, caller_id) and callers(tenant_id, id).
2. A Principal may hold multiple active delegations. A Caller may be delegated to more than one Principal; authorization is evaluated for the exact Principal/Caller pair.
3. A grant is direct. A Caller cannot create or forward delegations, so delegation chains are not implicit or transitive.
4. Any existing Caller kind (Anonymous, Authenticated, Service) may be selected explicitly. The Caller kind remains the authoritative type; it is not inferred from the Principal.
5. A Principal can grant and revoke only its own delegations. The trusted application transaction sets app.tenant_id and app.principal_id after authentication. Client DTOs must not set either value.
6. A grant is append-only history. Revocation is final and records revoked_at plus revoked_by_principal_id. Re-granting after revocation creates a new delegation_id; the partial unique index permits only one active grant for a given tenant/Principal/Caller tuple.
7. Granting requires an active Principal and an active Caller in the same tenant. Invocation-time resolution must re-check both states and the active delegation; a grant does not keep a revoked Caller or disabled Principal alive.
8. Runtime has SELECT on the delegation relation and EXECUTE on narrow grant/revoke functions, but no direct INSERT/UPDATE/DELETE privilege. The functions are SECURITY DEFINER, owned by qembed_definer, use a fixed search path, and validate the trusted tenant/Principal context.
9. The mapping table has tenant RLS with ENABLE and FORCE. The definer policy is limited to the function owner; runtime reads remain constrained by app.tenant_id.

## Revocation and invocation race

The begin-invocation transaction must resolve the exact active Principal/Caller delegation and lock that row with SELECT ... FOR SHARE before it inserts the invocation. The revocation function updates the same row. PostgreSQL row locking therefore orders the two operations: either begin-invocation commits while holding the lock before revocation, or it observes the revoked grant and fails. Provider I/O happens only after the invocation transaction commits.

The lock must be held until the begin-invocation transaction commits. A plain unlocked SELECT is insufficient for the revocation race.

## Rust integration contract

- The authentication adapter continues to authenticate against owner_principals / owner_credentials; SQL-011 does not replace that path.
- The trusted application layer carries the authenticated Principal separately from the selected Caller.
- The transaction context must set tenant and Principal IDs from trusted authentication state, never from request DTO fields.
- The runtime resolves an explicit Caller choice through principal_caller_delegations, checks Principal and Caller lifecycle state, and pins the Caller ID into object_invocations and the idempotency reservation.
- Idempotency is scoped by the effective Caller. Repeating the same key as a different Caller is a different idempotency scope.
- Anonymous and Service Callers remain distinct execution identities. Whether a transport is allowed to select a particular Caller is an application policy; possession of a Caller UUID alone is never authorization.

## Boundaries and follow-up

SQL-011 introduces the physical relation, grant/revoke functions, RLS/grants, and regression tests. It does not change the Rust Principal, Scope, or TenantTransaction implementation. The Rust follow-up must add trusted Principal context and a transaction-scoped delegation resolver/lock before RUST-036 can safely create invocations.

The app.* settings are trusted application context, just like the existing tenant setting. RLS and SECURITY DEFINER functions are not a defense against arbitrary SQL executed with the runtime database role; that role and its connection path must remain application-internal.

No automatic self-mapping, caller creation, transitive delegation, or fallback from missing delegation is permitted.
