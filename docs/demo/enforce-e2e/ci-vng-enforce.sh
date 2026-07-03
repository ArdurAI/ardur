#!/usr/bin/env bash
# vng --exec takes exactly one executable with no argument-passing syntax of
# its own (see kernel-enforce.yml's comment on the ardur-guard-smoke
# invocation this sits alongside), so this just hardcodes run.sh's mode
# argument rather than needing one.
set -eu
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/run.sh" enforce
