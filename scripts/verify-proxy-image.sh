#!/usr/bin/env bash
set -euo pipefail

IMAGE_REF="${1:?usage: verify-proxy-image.sh <image-ref>}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SMOKE_TMP="${TMPDIR:-/tmp}/ardur-proxy-image-smoke"
CONTAINER_NAME="ardur-proxy-smoke-${GITHUB_RUN_ID:-$$}-${RANDOM}"
API_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"

cleanup() {
    docker rm --force "$CONTAINER_NAME" >/dev/null 2>&1 || true
    rm -rf "$SMOKE_TMP"
}
trap cleanup EXIT

mkdir -p "$SMOKE_TMP"

test "$(docker image inspect --format '{{.Config.User}}' "$IMAGE_REF")" = "65532:65532"
test "$(docker image inspect --format '{{.Config.WorkingDir}}' "$IMAGE_REF")" = "/home/ardur"
docker image inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$IMAGE_REF" \
    | grep --fixed-strings --line-regexp 'VIBAP_HOME=/home/ardur/.ardur' >/dev/null
if docker image inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$IMAGE_REF" \
    | grep --extended-regexp '^(ARDUR_API_TOKEN|VIBAP_API_TOKEN)=' >/dev/null; then
    echo "image embeds an API token environment value" >&2
    exit 1
fi

docker run \
    --detach \
    --name "$CONTAINER_NAME" \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
    --tmpfs /home/ardur/.ardur:rw,nosuid,nodev,size=64m,uid=65532,gid=65532,mode=0700 \
    --env "VIBAP_API_TOKEN=$API_TOKEN" \
    --publish 127.0.0.1::8443 \
    "$IMAGE_REF" >/dev/null

test "$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$CONTAINER_NAME")" = "true"
test "$(docker inspect --format '{{json .HostConfig.CapDrop}}' "$CONTAINER_NAME")" = '["ALL"]'
docker inspect --format '{{json .HostConfig.SecurityOpt}}' "$CONTAINER_NAME" \
    | grep --fixed-strings 'no-new-privileges' >/dev/null

HOST_PORT="$(docker port "$CONTAINER_NAME" 8443/tcp | sed -n 's/.*://p')"
test -n "$HOST_PORT"
PROXY_URL="https://127.0.0.1:$HOST_PORT"

for _ in $(seq 1 60); do
    if curl --insecure --silent --show-error --fail "$PROXY_URL/health" >/dev/null 2>&1; then
        break
    fi
    if test "$(docker inspect --format '{{.State.Running}}' "$CONTAINER_NAME")" != "true"; then
        docker logs "$CONTAINER_NAME" >&2
        exit 1
    fi
    sleep 1
done
curl --insecure --silent --show-error --fail "$PROXY_URL/health" >/dev/null

ARDUR_API_TOKEN="$API_TOKEN" \
ARDUR_PROXY_URL="$PROXY_URL" \
TMPDIR="$SMOKE_TMP" \
    "$REPO_ROOT/scripts/verify-mvp.sh"

if docker logs "$CONTAINER_NAME" 2>&1 | grep --fixed-strings "$API_TOKEN" >/dev/null; then
    echo "proxy logs exposed the injected API token" >&2
    exit 1
fi

echo "validated hardened proxy image: $IMAGE_REF"
