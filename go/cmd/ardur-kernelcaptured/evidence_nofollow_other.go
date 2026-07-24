//go:build !linux && !darwin

package main

// evidenceOpenNoFollow is zero on platforms without O_NOFOLLOW support. The
// lexical prevalidation chain still rejects symlinked path components; the
// trailing-symlink TOCTOU hardening is unavailable here.
const evidenceOpenNoFollow = 0

// setRestrictiveUmask is a no-op on platforms without umask support.
func setRestrictiveUmask() {}
