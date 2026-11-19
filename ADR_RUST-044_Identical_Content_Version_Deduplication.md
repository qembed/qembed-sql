# RUST-044 — Identical-content object version semantics

**Status:** accepted project contract (2026-11-19)  
**Scope:** Owner create-version behavior and compatibility with the canonical snapshot schema. No DDL change.

## Context

The canonical schema defines `UNIQUE (tenant_id, object_id, content_hash)` on `snapshots`. Each snapshot is also bound by a composite foreign key to exactly one `(tenant_id, object_id, object_version_id)`.

Consequently, a second snapshot row for the same object and content hash cannot be inserted, and an existing snapshot cannot be attached to a different version without violating the version-bound identity contract.

T-30 requires repeated invocations of one configuration to reuse its snapshot and a binding change to produce a new snapshot. T-30 does not require a new object version for byte-identical content.

The original M0 v2.2 specification is unavailable. This decision is a newly approved project contract for RUST-044; it is not represented as recovered M0 behavior.

## Decision

At the Owner create-version boundary, the runtime performs version-level deduplication within the exact tenant/object identity:

1. Build and validate the candidate's exact RFC 8785/JCS canonical bytes and calculate SHA-256 over those bytes.
2. Look up existing snapshots for the same tenant/object and matching content hash, within the tenant-scoped transaction/Store boundary.
3. If a matching hash is found, compare the exact canonical bytes:
   - If the bytes are identical, do not insert an `object_version` or a `snapshot`. Return the stable `identical_content` outcome with the existing object-version and snapshot identifiers. The response must make clear that no new version was created.
   - If the bytes differ, fail closed with an integrity/hash-collision error. Never reuse the existing snapshot and never treat the candidate as a new distinct content version under the colliding digest.
4. If no existing snapshot has the candidate hash, create the draft object version and its snapshot in one tenant-scoped PostgreSQL transaction. Both inserts commit or roll back together.
5. PostgreSQL uniqueness and foreign-key constraints remain authoritative under concurrency. A uniqueness race must be resolved by re-reading the conflicting tenant/object/hash row and performing the same exact-byte comparison; it must not become an unverified success or a generic duplicate alias.

## Invariants

- Deduplication is scoped to the same tenant and object. Identical bytes in another tenant or another object do not deduplicate.
- SHA-256 is an index/lookup discriminator, not proof of byte equality. Exact canonical-byte comparison is mandatory before returning `identical_content`.
- A snapshot remains bound to its original object version. No cross-version snapshot reassignment or alias row is introduced.
- An `identical_content` result identifies the existing version and snapshot and does not mutate object state, version history, publication pointer, events, or outbox.
- Different content creates a new Draft version and snapshot atomically. Validation and publication remain separate operations.
- The existing schema uniqueness, composite foreign key, immutability, tenant RLS, and Store transaction boundaries are preserved.
- No schema migration or DDL change is required by this decision.

## Required application tests

1. Same tenant/object and identical canonical bytes returns `identical_content` with the existing version/snapshot IDs; row counts and object pointer/state remain unchanged.
2. Same tenant/object and same hash but different bytes returns an integrity error and creates no rows.
3. Same bytes under a different object or tenant do not deduplicate.
4. Different bytes create one new Draft version and one snapshot; both are committed together.
5. Injected failure on either insert leaves neither row.
6. Two concurrent requests for the same new content produce one stored version/snapshot; the loser re-reads and returns `identical_content` only after exact-byte equality is proven.
7. A concurrent same-hash/different-bytes condition fails closed.
8. Existing snapshot immutability and exact version FK remain intact.

These are RUST-044 application/Store acceptance requirements. They do not claim that the current SQL smoke suite has executed them.

## Consequences

The API must distinguish “created a new version” from “content already represented by an existing version.” Callers must not infer a new version identity from a successful HTTP response alone; the explicit outcome and returned identifiers are authoritative.

If the product later requires multiple distinct version identities for identical bytes, that is a different data model: separate content-addressed immutable blobs from version-to-content associations (or an equivalent reviewed design). Such a change requires a new qembed-sql ADR, DDL, migration/clean-schema update, and database tests before Rust implementation.

## Approval record

Approved explicitly by the project owner on 2026-11-19 in the RUST-044 architecture discussion. The proposal was tracked in [qembed-sql issue #16](https://github.com/qembed/qembed-sql/issues/16).
