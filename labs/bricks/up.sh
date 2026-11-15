#!/usr/bin/env bash
#
# Stand up the OWASP Bricks demo lab, provisioned and verified.
#
# Bricks keeps its MySQL data INSIDE the container and creates the `inject`
# database at runtime via config/setup.php. If setup.php is hit before mysqld
# has finished starting, the database is never created — and Bricks still serves
# a 200 with "Unable to connect to the database", so an HTTP-status check passes
# while the lab is actually dead (the silent-failure trap). This script waits for
# MySQL to accept connections BEFORE provisioning, then verifies the row count at
# the database level — not the HTTP status — so a broken lab fails loudly here.
#
# Usage:
#   labs/bricks/up.sh            # boot + provision + verify on 127.0.0.1:8904
#   PORT=8910 labs/bricks/up.sh  # use a different loopback port
#
# Requires: docker. The image is citizenstig/owaspbricks; if it is not present,
# pull it first with scripts/pull-legacy-image.sh (its manifest is schema1).
#
# Tear down with: docker rm -f nf-demo
set -euo pipefail

NAME="${NAME:-nf-demo}"
PORT="${PORT:-8904}"
IMAGE="citizenstig/owaspbricks"
BASE="http://127.0.0.1:${PORT}"

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "error: image '$IMAGE' not found locally." >&2
  echo "       pull it first: scripts/pull-legacy-image.sh ${IMAGE}:latest" >&2
  exit 1
fi

echo "▸ (re)starting container '$NAME' on ${BASE} (loopback-only)"
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" -p "127.0.0.1:${PORT}:80" "$IMAGE" >/dev/null

echo "▸ waiting for mysqld to accept connections"
for _ in $(seq 1 60); do
  if docker exec "$NAME" mysql -uroot -e "SELECT 1" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
if ! docker exec "$NAME" mysql -uroot -e "SELECT 1" >/dev/null 2>&1; then
  echo "error: mysqld did not become ready in time." >&2
  exit 1
fi

echo "▸ waiting for apache to serve"
for _ in $(seq 1 60); do
  if curl -fs -m3 -o /dev/null "${BASE}/" 2>/dev/null; then
    break
  fi
  sleep 1
done
if ! curl -fs -m3 -o /dev/null "${BASE}/" 2>/dev/null; then
  echo "error: apache did not become ready in time." >&2
  exit 1
fi

echo "▸ provisioning the 'inject' database via config/setup.php"
COUNT=""
for _ in $(seq 1 30); do
  curl -fsS -m20 "${BASE}/config/setup.php" -o /dev/null 2>/dev/null || true
  COUNT="$(docker exec "$NAME" mysql -uroot -N -e "use inject; select count(*) from users;" 2>/dev/null || true)"
  if [ -n "$COUNT" ] && [ "$COUNT" -ge 1 ] 2>/dev/null; then
    break
  fi
  sleep 1
done
if [ -z "$COUNT" ] || [ "$COUNT" -lt 1 ] 2>/dev/null; then
  echo "error: provisioning failed — 'inject.users' is empty or missing." >&2
  echo "       the lab would serve 'Unable to connect to the database'." >&2
  exit 1
fi

echo "✓ Bricks ready at ${BASE}  —  inject.users has ${COUNT} row(s)"
echo
echo "  run the demo scan:"
echo "    pnpm --filter @nightfall/cli dev -- --scope demo-bricks.scope.yaml"
echo
echo "  tear down:"
echo "    docker rm -f ${NAME}"
