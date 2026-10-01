#!/usr/bin/env bash
#
# tools/ci/deploy-image-pin-check.sh - reject mutable upstream image
# references in the reference deployment stack.
#
# Two builds at the same KiwiCaptcha commit must execute the same PHP,
# Alpine and Valkey bytes: every upstream FROM in deploy/Dockerfile and
# every upstream image: in deploy/*.yml must carry an immutable
# @sha256:<64hex> digest. A tag-only reference is a mutable input and is
# rejected; a locally built image (no upstream pull) is exempt and must
# be listed in LOCAL_IMAGE_ALLOWLIST below.
#
# Pure POSIX tooling: no network, no docker required.
#
# Usage: bash tools/ci/deploy-image-pin-check.sh
# Exit status: 0 when every reference is digest-pinned, 1 on the first
# mutable reference.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)
DEPLOY="$ROOT/deploy"

# Compose image names built from this repository (they have a build:
# section and are never pulled): exempt from upstream digest pinning.
LOCAL_IMAGE_ALLOWLIST='kiwicaptcha/reference-deployment'

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

pass() {
    echo "PASS: $*"
}

[ -d "$DEPLOY" ] || fail "missing deploy directory: $DEPLOY"

DIGEST_RE='@sha256:[0-9a-f]{64}$'

# ── Dockerfiles: every FROM must be digest-pinned ──────────────────────
dockerfiles=0
while IFS= read -r dockerfile; do
    dockerfiles=$((dockerfiles + 1))
    while IFS= read -r line; do
        ref=${line#*FROM }
        ref=${ref%% *}
        [ -n "$ref" ] || fail "$dockerfile: unparsable FROM line: $line"
        case "$ref" in
            scratch) continue ;;
        esac
        if ! printf '%s' "$ref" | grep -Eq "$DIGEST_RE"; then
            fail "$dockerfile: FROM $ref is not digest-pinned (expected image:tag@sha256:<64hex>)"
        fi
    done < <(grep -E '^[[:space:]]*FROM[[:space:]]' "$dockerfile" || true)
done < <(find "$DEPLOY" -type f -name 'Dockerfile*' | sort)
[ "$dockerfiles" -ge 1 ] || fail "no Dockerfile found under $DEPLOY"
pass "$dockerfiles Dockerfile(s): every FROM is digest-pinned"

# ── Compose files: every upstream image: must be digest-pinned ─────────
composefiles=0
while IFS= read -r compose; do
    composefiles=$((composefiles + 1))
    while IFS= read -r line; do
        ref=$(printf '%s' "$line" | sed -E 's/^[[:space:]]*image:[[:space:]]*//' | tr -d '"'"'"'')
        ref=${ref%%[[:space:]]*}
        [ -n "$ref" ] || fail "$compose: unparsable image line: $line"
        local_image=0
        for allowed in $LOCAL_IMAGE_ALLOWLIST; do
            if [ "$ref" = "$allowed" ]; then local_image=1; fi
        done
        [ "$local_image" = "1" ] && continue
        if ! printf '%s' "$ref" | grep -Eq "$DIGEST_RE"; then
            fail "$compose: image $ref is not digest-pinned (expected image:tag@sha256:<64hex>, or an explicitly allowlisted locally built image)"
        fi
    done < <(grep -E '^[[:space:]]+image:[[:space:]]' "$compose" || true)
done < <(find "$DEPLOY" -type f \( -name '*.yml' -o -name '*.yaml' \) | sort)
[ "$composefiles" -ge 1 ] || fail "no compose file found under $DEPLOY"
pass "$composefiles compose file(s): every upstream image is digest-pinned"

echo "deploy image pins: all upstream references immutable"
