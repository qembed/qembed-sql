#!/usr/bin/env bash
set -euo pipefail

# Test-only pgsodium preload key provider for the ephemeral CI container.
# The root key is persisted only inside the disposable PostgreSQL data volume.
key_file="${PGDATA}/pgsodium_root.key"
if [[ ! -s "${key_file}" ]]; then
  umask 077
  head -c 32 /dev/urandom | od -A n -t x1 | tr -d ' \n' > "${key_file}"
fi
cat "${key_file}"
