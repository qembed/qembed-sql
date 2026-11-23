# QSA-003 verifier build provenance

**Status:** CI candidate; not a release or production approval.

## Archived toolchain

The verifier builds use this exact OCI image reference:

`ghcr.io/qembed/qembed-sql/qsa003-toolchain@sha256:00058adbd06e8c28d00257af30fd75d60474e4d540e745c8c1420be8a6be912c`

The image was published to GHCR by the one-time bootstrap job in the immutable-toolchain preparation run. The digest identifies the published OCI manifest and its contents; ordinary verifier CI does not rebuild the image, resolve APT dependencies, or use a mutable tag. Both independent build jobs pull and run this same digest.

The archived image is based on the PostgreSQL 19 / pgvector Bookworm image pinned by its own digest. It retains:

- the installed Debian package/version inventory;
- the downloaded `.deb` package archives and their SHA-256 hashes;
- the APT source configuration used during bootstrap;
- SHA-256 hashes of the signed APT `InRelease` metadata;
- toolchain metadata including PostgreSQL, compiler, libsodium, source commit, and architecture.

The bootstrap build resolved packages from the configured repositories at that time. This is an explicit boundary: the archive preserves the resulting installed environment and available package evidence, but does not claim that the original APT repository state can be independently reconstructed forever. The published OCI image is the archived source of the exact installed toolchain used by subsequent builds.

Digest pinning guarantees content identity when the image is available from GHCR; it does not guarantee registry retention or prevent deletion. The repository maintainers must preserve the GHCR package, restrict deletion rights, and retain the digest reference in version control. The package must remain readable by GitHub Actions jobs using `packages: read`.

## What the workflow proves

`.github/workflows/qsa003-build-provenance.yml` performs two builds on separate GitHub-hosted `ubuntu-24.04` runners. Each build pulls the same archived OCI image by the digest above and performs no APT installation.

The jobs:

1. Check out the same workflow commit.
2. Pull and run the exact pinned toolchain image from GHCR.
3. Build the PostgreSQL C extension from the checked-out source.
4. Record the archived toolchain metadata, complete installed package inventory, and image digest.
5. Upload the binary and toolchain fingerprint separately.

The final job requires byte-identical shared objects, SHA-256 manifests, and toolchain fingerprints. It then creates a GitHub build-provenance attestation for the verified binary, verifies that attestation with GitHub CLI, and retains the binary and evidence as a workflow artifact.

## Evidence boundaries

The immutable digest freezes the archived OCI image contents used by the two builds. It does not freeze the GitHub-hosted runner image, host kernel, Docker engine, or GitHub Actions service. Nor does it establish that the bootstrap APT resolution was reproducible before the image was published.

The attestation proves the recorded GitHub build identity and subject digest. It does not replace independent security review, native-code audit, ABI compatibility testing, packaging/signing policy, or a supported PostgreSQL version matrix.

## Acceptance for this candidate

- Both independent build jobs pull and use the exact pinned OCI digest.
- Neither verifier build performs APT operations.
- The binary, SHA-256 manifest, toolchain metadata, and package inventory comparisons succeed.
- The generated attestation verifies against this repository.
- The workflow artifact contains the binary, SHA-256, toolchain fingerprint, and provenance summary.

Passing these checks is evidence for the candidate build path only. It does not authorize deployment or close QSA-003.
