# QSA-003 — pgsodium PostgreSQL 19 prototype

## Why this prototype exists

RT-050 requires an asymmetric verifier inside PostgreSQL while the signing private key stays outside the SQL runtime path. pgsodium 3.1.11 exposes libsodium Ed25519 detached-signature verification as `crypto_sign_verify_detached(sig, message, public_key)`. Its published documentation says PostgreSQL 14+ and libsodium 1.0.18+ are required. That is not, by itself, evidence that this release builds or behaves correctly on PostgreSQL 19.

References:
- PGXN release 3.1.11 (2026-06-10): https://www.pgxn.org/dist/pgsodium/3.1.11/  
- Exact source commit: https://github.com/michelp/pgsodium/commit/a8b8a2739bab1f7a07445b1c911e2bd1abf67784  
- Unsigned tag metadata: https://github.com/michelp/pgsodium/releases/tag/v3.1.11  
- Issue #127 disposition (closed by maintainer): https://github.com/michelp/pgsodium/issues/127
- pgsodium API documentation: https://github.com/michelp/pgsodium
- PostgreSQL 19 release notes: https://www.postgresql.org/docs/19/release-19.html

## Pinned source and provenance caveat

The build uses the exact source commit `a8b8a2739bab1f7a07445b1c911e2bd1abf67784`, referenced by tag `v3.1.11`. GitHub reports that annotated tag as **unsigned**. An issue (#127) that requested signed release provenance was closed by the maintainer, who characterized the request as AI spam; it is not evidence of an upstream security commitment or response. Pinning the commit makes the experiment reproducible but does not authenticate who published it. Before production adoption, independently verify the source and build provenance or choose a distribution process with an authenticated chain of custody.

## What CI proves

The dedicated workflow builds the pinned PGXN 3.1.11 source against the PostgreSQL 19 server headers in the same PostgreSQL 19 / pgvector 0.8.7 image used by the SQL smoke suite. It then:
1. installs and creates the extension;
2. creates an Ed25519 keypair and verifies a valid signature;
3. rejects a modified message;
4. removes PUBLIC execute access to pgsodium functions;
5. grants the runtime role only schema USAGE and EXECUTE on the detached verifier;
6. verifies that the runtime role can verify, but cannot sign or generate keypairs.

This is a build/API/ACL feasibility probe only. It does not validate RT-050's transaction binding, key rotation, verifier ownership model, issuer, or pool lifecycle.

## Important deployment and trust questions still open

- pgsodium is a native C extension loaded into the PostgreSQL server process. Its source, release provenance, build flags, binary packages, and update policy become part of the database trusted computing base.
- The general PostgreSQL 14+ statement does not establish an explicit upstream PostgreSQL 19 support commitment. This CI probe gives reproducible evidence for this exact image/build, not vendor certification.
- The probe intentionally revokes PUBLIC execute and grants one verifier function. Production must validate the extension's full ACL/default-privilege behavior, function owner, schema owner, extension update scripts, and any functions requiring elevated roles.
- No pgsodium secret-key management feature is needed for RT-050 if PostgreSQL stores only public verification keys. Do not enable or expose signing/key-generation functions to `qembed_runtime`.
- The project must still decide whether to vendor/build the extension, use a maintained distribution package, or choose a separately audited verifier.

## Acceptance status

A green workflow is a prerequisite, not approval to adopt pgsodium. RT-050 remains proposed until the full transaction-binding and adversarial SQL prototype passes and the project owner approves the complete design.
