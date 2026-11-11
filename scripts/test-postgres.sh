#!/usr/bin/env bash
# PostgreSQL parity suite (ticket 12, ADR-0005): run the full behavior
# suite against a real, throwaway PostgreSQL instance.
#
#   scripts/test-postgres.sh            # docker run postgres:alpine + cargo test
#   BARK_TEST_PG_DSN=... scripts/test-postgres.sh   # external instance, skip docker
#
# With BARK_TEST_PG_DSN unset, a postgres:alpine container is started on an
# ephemeral port and removed on exit. The suite itself runs the SQLite
# default AND the PostgreSQL parity mode in one invocation: tests that
# consume tests/common::ephemeral_config switch backends on
# BARK_TEST_PG_DSN; SQLite-default-pinned tests (the store-file assertions)
# keep asserting SQLite. Requires: docker, cargo.
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ -z "${BARK_TEST_PG_DSN:-}" ]]; then
    command -v docker >/dev/null || { echo "docker not available; set BARK_TEST_PG_DSN instead" >&2; exit 1; }
    CONTAINER=$(docker run -d \
        -e POSTGRES_USER=bark -e POSTGRES_PASSWORD=bark -e POSTGRES_DB=bark \
        -p 127.0.0.1::5432 postgres:alpine)
    cleanup() { docker rm -f "$CONTAINER" >/dev/null 2>&1 || true; }
    trap cleanup EXIT

    PORT=$(docker port "$CONTAINER" 5432/tcp | head -1 | sed 's/.*://')
    for _ in $(seq 1 60); do
        docker exec "$CONTAINER" pg_isready -U bark -q 2>/dev/null && break
        sleep 1
    done
    docker exec "$CONTAINER" pg_isready -U bark -q || { echo "postgres did not become ready" >&2; exit 1; }
    export BARK_TEST_PG_DSN="postgres://bark:bark@127.0.0.1:${PORT}/bark"
    echo "== ephemeral postgres:alpine on 127.0.0.1:${PORT} =="
fi

cargo test --no-fail-fast
