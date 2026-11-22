#!/usr/bin/env bash
set -euo pipefail

# Test-only provider: pgsodium requires a root key when preloaded.
# The probe uses only raw Ed25519 public-key verification, not server-managed keys.
# Return a fresh ephemeral 32-byte key; do not persist it in the CI container.
head -c 32 /dev/urandom | od -A n -t x1 | tr -d ' \n'
