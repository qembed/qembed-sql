# QSA-003 verifier build provenance

**Status:** CI candidate; not a release or production approval.

## What the workflow proves

`.github/workflows/qsa003-build-provenance.yml` performs two builds on separate GitHub-hosted `ubuntu-24.04` runners. Each build runs in a fresh container based on the PostgreSQL 19 / pgvector Bookworm image pinned by its OCI manifest digest.

The jobs:

1. Check out the same workflow commit.
2. Install the verifier build dependencies.
3. Normalize the source path and archive timestamps where supported.
4. Build the PostgreSQL C extension from the checked-out source.
5. Record the source commit timestamp, base image reference, PostgreSQL/compiler/libsodium versions, and exact Debian package versions.
6. Upload the binary and toolchain fingerprint separately.

The final job requires byte-identical shared objects, SHA-256 manifests, and toolchain fingerprints. It then creates a GitHub build-provenance attestation for the verified binary, verifies that attestation with GitHub CLI, and retains the binary and evidence as a workflow artifact.

## What this does not yet prove

The base OCI image is pinned by digest, but dependency installation currently uses the configured APT repositories at workflow execution time. The two independent jobs compare the resolved package versions and fail closed if their fingerprints differ; this is a same-run consistency gate, not a permanent lock on package repository state.

A future release-grade reproducibility gate must pin an immutable Debian/PGDG snapshot or use a separately built and reviewed toolchain image pinned by digest, and must demonstrate a rebuild from that archived toolchain at a later time. The GitHub-hosted runner image is also a managed environment; the container isolates the compiler and PostgreSQL build dependencies but does not make the host kernel or Docker engine bit-for-bit immutable.

The attestation proves the recorded GitHub build identity and subject digest. It does not replace independent security review, native-code audit, ABI compatibility testing, packaging/signing policy, or a supported PostgreSQL version matrix.

## Acceptance for this candidate

- Both independent build jobs succeed.
- The binary and toolchain fingerprint comparisons succeed.
- The generated attestation verifies against this repository.
- The workflow artifact contains the binary, SHA-256, toolchain fingerprint, and provenance summary.

Passing these checks is evidence for the candidate build path only. It does not authorize deployment or close QSA-003.
