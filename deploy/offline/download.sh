#!/usr/bin/env bash
# Fetch everything backend-iam needs, on a machine WITH internet and Docker.
# Then carry the repository (with vendor/wheels) and offline-bundle/ to the offline side.
#
#   deploy/offline/download.sh                         # wheels + base image (required)
#   deploy/offline/download.sh --optional              # + postgres and mermaid-cli images
#   deploy/offline/download.sh --debs ubuntu:24.04     # + Docker engine .debs for that distro
#                                                       (repeatable; use the servers' distro)
# Every wheel is checked against its sha256 in requirements*.lock.txt.
set -euo pipefail

cd "$(dirname "$0")/../.."
ROOT=$PWD
BUNDLE=$ROOT/offline-bundle
BASE_IMAGE=python:3.14.7-slim-trixie
BASE_DIGEST=sha256:51dafde81dbdb6ebde285137a295cf18a47ca95234fe388a343719cb97305b3d
# Images are saved for the servers' platform only: multi-platform tarballs from Docker
# Desktop reference layers of other platforms and do not load on older engines.
PLATFORM=${PLATFORM:-linux/amd64}
OPTIONAL=0
DEBS=()

while [ $# -gt 0 ]; do
  case $1 in
    --optional) OPTIONAL=1 ;;
    --debs) DEBS+=("$2"); shift ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
  shift
done

# Git Bash on Windows: keep container paths as they are.
export MSYS_NO_PATHCONV=1
host_path() { if command -v cygpath >/dev/null; then cygpath -w "$1"; else echo "$1"; fi; }

mkdir -p "$BUNDLE/images" vendor/wheels

echo "== base image $BASE_IMAGE"
docker pull -q --platform "$PLATFORM" "$BASE_IMAGE"
got=$(docker image inspect "$BASE_IMAGE" --format '{{join .RepoDigests " "}}')
case $got in *"$BASE_DIGEST"*) ;; *) echo "digest mismatch for $BASE_IMAGE: $got" >&2; exit 1 ;; esac
docker save --platform "$PLATFORM" -o "$(host_path "$BUNDLE/images/python-3.14.7-slim-trixie.tar")" "$BASE_IMAGE"

echo "== proxy image backend-iam-proxy:1.27 (from nginx:1.27-alpine)"
docker pull -q --platform "$PLATFORM" nginx:1.27-alpine
# Re-tagged through a one-line build: a plain single-platform image that saves and
# loads everywhere (some multi-platform images do not export from Docker Desktop).
echo "FROM nginx:1.27-alpine" | docker build -q --platform "$PLATFORM" --provenance=false   --sbom=false -t backend-iam-proxy:1.27 - >/dev/null
docker save --platform "$PLATFORM" -o "$(host_path "$BUNDLE/images/backend-iam-proxy-1.27.tar")" backend-iam-proxy:1.27
rm -f "$BUNDLE/images/nginx-1.27-alpine.tar"

echo "== python wheels -> vendor/wheels (Linux x86_64, CPython 3.14, hashes enforced)"
docker run --rm -v "$(host_path "$ROOT"):/src" -w /src "$BASE_IMAGE" \
  pip download --quiet --no-deps --only-binary=:all: --require-hashes \
    -r requirements-dev.lock.txt -d vendor/wheels

if [ "$OPTIONAL" = 1 ]; then
  for img in postgres:17-alpine minlag/mermaid-cli:11.4.2; do
    echo "== optional image $img"
    docker pull -q --platform "$PLATFORM" "$img"
    docker save --platform "$PLATFORM" -o "$(host_path "$BUNDLE/images/$(echo "$img" | tr '/:' '--').tar")" "$img"
  done
fi

for distro in "${DEBS[@]}"; do
  name=$(echo "$distro" | tr ':/' '--')
  out="$BUNDLE/debs/$name"
  echo "== Docker engine packages for $distro -> $out"
  mkdir -p "$out"
  docker run --rm -v "$(host_path "$out"):/out" "$distro" bash -c '
    set -e
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    pkgs="docker.io"
    # Newer releases ship the CLI separately.
    if apt-cache show docker-cli >/dev/null 2>&1; then pkgs="$pkgs docker-cli"; fi
    apt-get install -y -qq --download-only --no-install-recommends $pkgs
    cp /var/cache/apt/archives/*.deb /out/
    echo "$pkgs" > /out/PACKAGES'
done

echo "== checksums"
( cd "$BUNDLE" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS )
( cd vendor/wheels && sha256sum ./*.whl > SHA256SUMS )

echo
echo "Done. Copy to the offline side:"
echo "  - this repository, including vendor/wheels/ ($(ls vendor/wheels/*.whl | wc -l) wheels)"
echo "  - offline-bundle/ ($(du -sh "$BUNDLE" | cut -f1))"
echo "Then on the build machine: docker load -i offline-bundle/images/python-3.14.7-slim-trixie.tar"
