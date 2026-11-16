#!/usr/bin/env bash
#
# Pull a legacy Docker image whose manifest is the old schema1 format
# (application/vnd.docker.distribution.manifest.v1+prettyjws), which Docker
# Engine 28+/containerd 2.1 refuses with:
#
#   not implemented: media type "...manifest.v1+prettyjws" is no longer supported
#
# Many classic vulnerable-web-app images (xvwa, owaspbricks, old mutillidae, …)
# were pushed years ago in schema1 and can no longer be pulled directly. This
# converts schema1 -> schema2 (v2s2) with skopeo in a throwaway container and
# loads the result into the local daemon, so the image becomes usable normally.
#
# Usage:
#   scripts/pull-legacy-image.sh <image-ref> [<image-ref> ...]
#
# Example:
#   scripts/pull-legacy-image.sh tuxotron/xvwa:latest citizenstig/owaspbricks:latest
#
# Requires: docker (the only dependency; skopeo runs from quay.io/skopeo/stable).
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <image-ref> [<image-ref> ...]" >&2
  exit 2
fi

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

for ref in "$@"; do
  if docker image inspect "$ref" >/dev/null 2>&1; then
    echo "==> $ref already present, skipping"
    continue
  fi
  echo "==> converting $ref (schema1 -> v2s2) and loading"
  safe="$(echo "$ref" | tr '/:' '__').tar"
  docker run --rm -v "$workdir":/out quay.io/skopeo/stable \
    copy --format v2s2 --dest-compress \
    "docker://$ref" "docker-archive:/out/$safe:$ref"
  docker load -i "$workdir/$safe"
  rm -f "$workdir/$safe"
  echo "==> done: $ref"
done
