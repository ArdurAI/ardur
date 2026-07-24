//go:build linux || darwin

package main

import "syscall"

// evidenceOpenNoFollow adds O_NOFOLLOW to the evidence-log append path so
// that a symlink placed at the target between the prevalidation Lstat and the
// OpenFile cannot redirect writes. This closes the Lstat→OpenFile TOCTOU
// window in appendKernelReceipt / recordTamperAudit / appendEnforceEvent.
//
// O_NOFOLLOW only rejects a trailing symlink; it does not reject symlinks in
// intermediate path components. The prevalidation chain
// (prevalidateKernelReceiptParentChain) already rejects symlinked parents, so
// together the two checks cover the full path.
const evidenceOpenNoFollow = syscall.O_NOFOLLOW
