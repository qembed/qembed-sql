# QSA-003 — pgsodium PostgreSQL 19 prototype

## Why this prototype exists

RT-050 requires an asymmetric verifier inside PostgreSQL while the signing private key stays outside the SQL runtime path. pgsodium 3.1.11 exposes libsodium Ed25519 detached-signature verification as `crypto_sign_verify_detached(sig, message, public_key)`. Its published documentation says PostgreSQL 14+ and libsodium 1.0.18+ are required. That is not, by itself, evidence that this release builds or behaves correctly on PostgreSQL 19.

References:
- PGXN release 3.1.11 (2026-06-10): https://www.pgxn.org/dist/pgsodium/3.1.11/  
- Exact pgsodium source commit: https://github.com/michelp/pgsodium/commit/a8b8a2739bab1f7a07445b1c911e2bd1abf67784  
- libsodium 1.0.22 signed tag: https://github.com/jedisct1/libsodium/releases/tag/1.0.22  
- Verified pgsodium source commit: https://github.com/michelp/pgsodium/commit/a8b8a2739bab1f7a07445b1c911e2bd1abf67784  
- Unsigned tag metadata: https://github.com/michelp/pgsodium/releases/tag/v3.1.11  
- Issue #127 disposition (closed by maintainer): https://github.com/michelp/pgsodium/issues/127
- pgsodium API documentation: https://github.com/michelp/pgsodium
- PostgreSQL 19 release notes: https://www.postgresql.org/docs/19/release-19.html

## Pinned source and provenance caveat

The build downloads pgsodium from exact source commit `a8b8a2739bab1f7a07445b1c911e2bd1abf67784`. GitHub reports the **commit signature as valid**, while the annotated `v3.1.11` tag object itself is unsigned. Because the workflow downloads the archive by commit SHA (not by tag or mutable branch), the source used by CI is bound to the verified commit. There is no separately verified signature on a prebuilt pgsodium release artifact in this prototype; production builds should continue to pin and verify the signed source commit or use an authenticated package process. The first build attempt exposed an additional dependency detail: pgsodium 3.1.11's new ipcrypt source uses libsodium 1.0.22 symbols, while Debian Bookworm supplies 1.0.18. The prototype builds libsodium 1.0.22 from commit `77e1ce5d6dee871c49ef211222ba18ef0c486bda`; GitHub reports the corresponding `1.0.22` tag signature as valid. The pgsodium link step passes `/usr/local/lib/libsodium.so` as an absolute link input and asserts with `ldd` that `pgsodium.so` resolves `libsodium.so.26`; the base image's old `libsodium.so.23` must not be selected by the linker. The server is restarted after installing it because PostgreSQL had already loaded the older shared library when the container started. An issue (#127) that requested signed release provenance was closed by the maintainer as AI spam; it is not evidence of an upstream security commitment or response.

## What CI proves

The dedicated workflow builds the pinned pgsodium 3.1.11 source against PostgreSQL 19 server headers in the PostgreSQL 19 / pgvector 0.8.7 image. It builds libsodium 1.0.22, verifies the pgsodium link resolves `libsodium.so.26`, and then configures pgsodium in `shared_preload_libraries`.

The preload is necessary for pgsodium to define `pgsodium.enable_event_trigger`; without it, pgsodium's DDL event trigger fails during later table creation because the setting is unknown. Preload also requires a getkey script and loads a root key into PostgreSQL server memory. CI uses `tests/pgsodium_getkey_test.sh` to return a fresh random 32-byte root key at startup without persisting it. This is safe for this probe only because it does not use pgsodium server-managed key derivation or key-ID APIs; it is a test fixture, not a production key-management recommendation.

The workflow then:
1. installs and creates the extension;
2. creates an Ed25519 keypair and verifies a valid detached signature;
3. rejects a modified signature/message;
4. removes PUBLIC execute access to pgsodium functions;
5. grants the runtime role only schema USAGE and EXECUTE on the detached verifier;
6. verifies that the runtime role can verify, but cannot sign or generate keypairs;
7. verifies a test-only signed context bound to backend PID, transaction ID, database OID and provisioned deployment/audience;
8. rejects wrong backend/database/deployment, expiry, altered signature, and replay after commit, rollback, or use from another backend;
9. confirms savepoint rollback preserves the outer transaction context and `pg_current_xact_id()` works in a `READ ONLY` transaction;
10. compares test-only RLS policies using a direct verifier helper and an uncorrelated scalar subquery that plans as an `InitPlan`.

The RLS microbenchmark scanned 10,000 rows (5,000 visible to the signed tenant) without a tenant index. Direct verification in the policy took 855.463 ms and 30,064 shared buffer hits; the `InitPlan` form took 1.143 ms and 67 shared buffer hits. This is a CI microbenchmark, not a production performance guarantee. It shows that production RLS policy design must preserve one context verification per statement, not repeat Ed25519 verification for each scanned row.

The tested code passed [prototype workflow run #35](https://github.com/qembed/qembed-sql/actions/runs/45021654908) and [SQL smoke run #253](https://github.com/qembed/qembed-sql/actions/runs/45021654841) on commit `a90f5e16cf04a47477f2a196d4b50d1c5b15b181`.

This remains a feasibility probe only. It does not validate a real Context Issuer, Rust transaction API, production RLS migration, cross-cluster replay with two real clusters, Caller delegation/revocation races, key rotation/revocation, issuer outage, retry orchestration, or actual connection-pool lifecycle.

## Important deployment and trust questions still open

- pgsodium is a native C extension loaded into the PostgreSQL server process. Its source, release provenance, build flags, binary packages, and update policy become part of the database trusted computing base.
- The general PostgreSQL 14+ statement does not establish an explicit upstream PostgreSQL 19 support commitment. This CI probe gives reproducible evidence for this exact image/build, not vendor certification.
- The probe intentionally revokes PUBLIC execute and grants one verifier function. Production must validate the extension's full ACL/default-privilege behavior, function owner, schema owner, extension update scripts, and any functions requiring elevated roles.
- The Ed25519 verifier itself uses public verification keys and does not need a signing key. However, preloading this pgsodium build also requires a getkey script and loads a server root key into memory. Production must explicitly decide whether this additional root-key lifecycle is acceptable and how it will be provisioned, protected, rotated and recovered.
- Do not grant signing or key-generation functions to `qembed_runtime`.
- The project must still decide whether to vendor/build the extension, use a maintained distribution package, or choose a separately audited verifier.
- The RLS `InitPlan` pattern must be checked against actual production policies and representative data/indexes; the CI result is not a substitute for a production workload benchmark.

## Additional transaction-binding constraint

The RT-050 token audience must identify the exact PostgreSQL deployment/database (for example, a provisioned cluster identifier plus database OID), not merely the backend PID and transaction ID. PID and transaction identifiers are meaningful within a database cluster; they are not globally unique across independently deployed clusters. A token copied between two clusters that happen to have the same PID/XID values must still fail. Add an explicit cross-cluster replay test before treating transaction binding as complete.

## Acceptance status

A green workflow is a prerequisite, not approval to adopt pgsodium. RT-050 remains proposed until the full transaction-binding and adversarial SQL prototype passes and the project owner approves the complete design.
