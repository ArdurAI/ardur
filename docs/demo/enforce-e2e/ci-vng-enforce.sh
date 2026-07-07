#!/usr/bin/env bash
# vng --exec takes exactly one executable with no argument-passing syntax of
# its own (see kernel-enforce.yml's comment on the ardur-guard-smoke
# invocation this sits alongside), so this just hardcodes run.sh's mode
# argument rather than needing one.
set -eu

# virtme-ng boots the host rootfs read-only, so run.sh's default OUT=/out
# (mkdir -p) fails with "Read-only file system". Point it at a writable tmpfs.
# Ensure /tmp is writable first (a minimal guest may leave it on the read-only
# rootfs), then hand run.sh a fresh dir under it via OUT_BASE.
if ! touch /tmp/.ardur-write-test 2>/dev/null; then
  mount -t tmpfs tmpfs /tmp
fi
rm -f /tmp/.ardur-write-test 2>/dev/null || true
OUT_BASE="$(mktemp -d /tmp/ardur-demo-out.XXXXXX)"
export OUT_BASE

exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/run.sh" enforce
