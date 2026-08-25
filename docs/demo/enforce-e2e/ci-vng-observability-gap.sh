#!/usr/bin/env bash
# vng --exec takes exactly one executable with no argument-passing syntax of
# its own, so this wrapper hardcodes the enforce mode used to exercise the
# kernel-stopped launch handoff, BPF denial, and receipt-correlation data plane.
set -eu

# virtme-ng boots the host rootfs read-only. Give the demo a writable tmpfs
# location for its output and Ardur home instead of its Docker default /out.
if ! touch /tmp/.ardur-write-test 2>/dev/null; then
  mount -t tmpfs tmpfs /tmp
fi
rm -f /tmp/.ardur-write-test 2>/dev/null || true
OUT_BASE="$(mktemp -d /tmp/ardur-demo-out.XXXXXX)"
export OUT_BASE

exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/run.sh" enforce
