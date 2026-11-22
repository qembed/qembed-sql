# QSA-003 — pgsodium PostgreSQL 19 prototype

## Why this prototype exists

RT-050 requires an asymmetric verifier inside PostgreSQL while the signing private key stays outside the SQL runtime path. pgsodium 3.1.11 exposes libsodium Ed25519 detached-signature verification as `crypto_sign_verify_detached(sig, message, public_key)`. Its published documentation says PostgreSQL 14+ and libsodium 1.0.18+ are required. That is not, by itself, evidence that this release builds or behaves correctly on PostgreSQL 19.

References:
- PGXN release 3.1.11 (2026-06-10): https://www.pgxn.org/dist/pgsodium/3.1.11/  
- Exact pgsodium source commit: https://github.com/michelp/pgsodium/commit/a8b8a2739bab1f7a07445b1c911e2bd1abf67784  
- libsodium 1.0.22 signed tag: https://github.com/jedisct1/libsodium/releases/tag/1.0.22  
- Unsigned tag metadata: https://github.com/michelp/pgsodium/releases/tag/v3.1.11  
- Issue #127 disposition (closed by maintainer): https://github.com/michelp/pgsodium/issues/127
- pgsodium API documentation: https://github.com/michelp/pgsodium
- PostgreSQL 19 release notes: https://www.postgresql.org/docs/19/release-19.html

## Pinned source and provenance caveat

The build uses the exact pgsodium source commit `a8b8a2739bab1f7a07445b1c911e2bd1abf67784`, referenced by tag `v3.1.11`. GitHub reports that annotated tag as **unsigned**. The first build attempt exposed an additional dependency detail: pgsodium 3.1.11's new ipcrypt source uses libsodium 1.0.22 symbols, while Debian Bookworm supplies 1.0.18. The prototype now builds libsodium 1.0.22 from commit `77e1ce5d6dee871c49ef211222ba18ef0c486bda`; GitHub reports the corresponding `1.0.22` tag signature as valid. This verifies the dependency version and provides a stronger provenance chain for libsodium, but does not resolve pgsodium's unsigned tag. An issue (#127) that requested signed release provenance was closed by the maintainer, who characterized the request as AI spam; it is not evidence of an upstream security commitment or response. Pinning the commit makes the experiment reproducible but does not authenticate who published it. Before production adoption, independently verify the source and build provenance or choose a distribution process with an authenticated chain of custody.

## What CI proves

The dedicated workflow builds the pinned pgsodium 3.1.11 source against PostgreSQL 19 server headers in the same PostgreSQL 19 / pgvector 0.8.7 image used by the SQL smoke suite. It first builds libsodium 1.0.22 because the distribution's Bookworm package (1.0.18) is too old for pgsodium 3.1.11's ipcrypt implementation. It then:
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
