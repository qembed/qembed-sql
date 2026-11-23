# Archived QSA-003 build toolchain.
# The resulting OCI image is published once and consumed by immutable digest.
FROM pgvector/pgvector:0.8.7-pg19-bookworm@sha256:9fd1e61398799f1d6b64a852bce2bb59863c0ebbcd96178e20c7b10059e9ea5e

ARG TOOLCHAIN_SOURCE_COMMIT
LABEL org.opencontainers.image.title="QSA-003 PostgreSQL 19 verifier build toolchain"
LABEL org.opencontainers.image.description="Archived compiler, PostgreSQL headers, libsodium and APT package evidence for QSA-003"
LABEL org.opencontainers.image.source="https://github.com/qembed/qembed-sql"
LABEL org.opencontainers.image.revision="${TOOLCHAIN_SOURCE_COMMIT}"

RUN set -eux; \
    export DEBIAN_FRONTEND=noninteractive; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      build-essential pkg-config libsodium-dev postgresql-server-dev-19; \
    test "$(pg_config --version | cut -d' ' -f1-2)" = "PostgreSQL 19.0"; \
    install -d /opt/qsa003/toolchain /opt/qsa003/debs; \
    cp -a /var/cache/apt/archives/*.deb /opt/qsa003/debs/ 2>/dev/null || true; \
    dpkg-query -W -f='${binary:Package}=${Version}\n' | sort \
      > /opt/qsa003/toolchain/dpkg-packages.txt; \
    { \
      echo "base_image=pgvector/pgvector:0.8.7-pg19-bookworm@sha256:9fd1e61398799f1d6b64a852bce2bb59863c0ebbcd96178e20c7b10059e9ea5e"; \
      echo "source_commit=${TOOLCHAIN_SOURCE_COMMIT}"; \
      echo "postgres=$(pg_config --version)"; \
      echo "compiler=$(cc -dumpfullversion -dumpversion)"; \
      echo "libsodium=$(pkg-config --modversion libsodium)"; \
      echo "architecture=$(dpkg --print-architecture)"; \
    } > /opt/qsa003/toolchain/metadata.txt; \
    (cd /opt/qsa003/debs && sha256sum *.deb > SHA256SUMS) 2>/dev/null || true; \
    cp -a /etc/apt/sources.list /opt/qsa003/toolchain/ 2>/dev/null || true; \
    cp -a /etc/apt/sources.list.d /opt/qsa003/toolchain/; \
    find /var/lib/apt/lists -maxdepth 1 -type f -name '*InRelease' -exec sha256sum {} + \
      > /opt/qsa003/toolchain/apt-inrelease-sha256.txt; \
    chmod -R a-w /opt/qsa003
