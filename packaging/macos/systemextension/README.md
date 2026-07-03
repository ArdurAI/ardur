# Ardur Endpoint Security extension — scaffold

Epic A (#63), Slice 2 remainder. This directory is a **scaffold**: it pins
down the exact shape a real macOS Endpoint Security (ES) System Extension
will take, without shipping code that cannot run or be tested today.

## Why this can't run yet

`es_new_client()` refuses to create a client unless the calling binary's code
signature carries the `com.apple.developer.endpoint-security.client`
entitlement. Apple grants that entitlement only after a manual review — it
cannot be self-assigned, even with a paid Developer ID. Until it is granted
for the `ardur-kernelcaptured` signing identity, everything in this
directory is reference material for the implementation that follows, not a
buildable artifact. See the tracking issue filed alongside this scaffold for
the entitlement request itself.

## Files

| File | Role |
|---|---|
| `Info.plist` | System Extension bundle manifest (`NSExtensionPointIdentifier = com.apple.system_extension.endpoint_security`). Would live at `ArdurEndpointSecurity.systemextension/Contents/Info.plist` inside a real app bundle. |
| `ArdurEndpointSecurity.entitlements` | The entitlement the extension's code signature needs. |
| `EndpointSecurityClient.swift` | Reference implementation of the ES subscribe/decode path (`es_new_client` → `es_subscribe(ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_EXIT)` → project into `ArdurProcessEvent`, a shape mirroring Go's `kernelcapture.ProcessEvent`). Type-checks cleanly against the real `EndpointSecurity.framework` headers (`swiftc -typecheck`) on a machine with Xcode command line tools installed — this was verified while writing it, not just hand-typed against documentation. |

The Go-side counterpart lives at `go/pkg/kernelcapture/es_client_darwin.go`:
the `ESClient` interface this extension is expected to eventually feed, and
`InspectEndpointSecurityPreflight()`, a real (not scaffolded) check of
whether the running binary currently carries the entitlement — wired into
`ardur-sensor preflight`.

## What is explicitly NOT here

- **Packaging/signing.** System Extensions cannot be distributed standalone;
  they must be embedded in a signed, notarized host application and
  activated via `SystemExtensions.framework` (`OSSystemExtensionRequest`)
  from that host app. None of that harness exists here.
- **The hand-off transport.** Once the extension observes events, something
  has to get them to `ardur-kernelcaptured`. The natural choice is a local
  Unix socket (mirroring the daemon's own control-plane socket pattern), but
  it is not designed or implemented — see the `TODO(#es-hand-off)` marker in
  `EndpointSecurityClient.swift`.
- **Enforcement (`AUTH_*` events).** This scaffold only subscribes to
  `NOTIFY_EXEC`/`NOTIFY_EXIT` (observation, matching the Linux eBPF
  tracepoint consumer's scope). The macOS analogue of `process_guard.bpf.c`'s
  BPF-LSM enforcement hooks (`AUTH_EXEC`, `AUTH_OPEN`, etc., which can deny an
  action rather than just observe it) is future work once observation alone
  is proven out.

## Next steps once the entitlement is granted

1. Stand up a minimal host app target that embeds this extension bundle and
   calls `OSSystemExtensionRequest.activationRequest`.
2. Design and implement the hand-off transport.
3. Replace `go/pkg/kernelcapture/es_client_darwin.go`'s `NewESClient` stub
   with a real client reading from that transport.
4. Wire `go/cmd/ardur-kernelcaptured/daemon_darwin.go`'s `runEBPFConsumer`
   the same way `runGuardConsumer` (Linux) wires the BPF-LSM guard today.
