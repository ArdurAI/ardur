# kernelcapture proof harness

This package is the Ardur Linux proof harness for process-exec capture with paired process-exit lifecycle metadata and kernel-effect synthetic receipts.

## What it currently does

- Correlates `exec` / `exit` process events to tool-call receipt candidates.
- Emits synthetic kernel-effect receipt fields, including:
  - `correlation_method`
  - `correlation_confidence`
  - `coverage_status`
  - `capture_loss`
- Enforces honesty behavior:
  - ambiguous attribution => `insufficient_evidence`
  - degraded/unknown coverage => `insufficient_evidence`
  - capture loss / consumer lag => degraded `insufficient_evidence`
  - daemon restart gap => unknown `insufficient_evidence`
- Includes a Linux-only Phase 2 eBPF MVP smoke path that:
  - loads the embedded `sched/sched_process_exec` + `sched/sched_process_exit` eBPF tracepoint programs.
  - reads scoped process exec+exit lifecycle samples from a ringbuf.
  - runs deterministic root and child commands.
  - projects the observed exec and exit events through the same correlator.
- Includes a local-only daemon custody scaffold and read-only preflight
  inspector for the future root-owned config/state/socket/bpffs boundary
  without installing, starting, binding, or pinning anything.
- Defines the local JSON-line launch-wrapper-to-daemon protocol contract,
  daemon-observed peer authorization, protocol/peer handshake contract, a Linux
  SO_PEERCRED retrieval seam for already-owned Unix connections, and a dry-run
  accept-loop plan; no server, listener, socket bind, daemon install, or daemon
  start exists.
- Adds a local launch-wrapper session proof seam that converts generic CLI
  boundary metadata into a validated `register_session` request and a
  correlator seed receipt for the root process; it does not run commands,
  start a daemon, or capture subprocess/file/network side effects.

## Capture sources

1. `RunLinuxEBPFExecSmoke` (Linux only, privileged/gated)
   - Loads the generated eBPF object with `github.com/cilium/ebpf`.
   - Attaches `sched/sched_process_exec` and `sched/sched_process_exit` through tracefs/debugfs.
   - Emits metadata-only lifecycle events: PID, PPID, TID, PID namespace id, cgroup id, monotonic timestamp, `comm`, and `exit_code` on exit events.
   - Does not collect argv, env, file contents, network destinations, or raw command payloads.

2. `RingbufProcessSource` (Linux only)
   - Uses `github.com/cilium/ebpf` ringbuf reader.
   - Supports an already-pinned ringbuf map path for future daemon integration.
   - Reads a fixed process-lifecycle sample layout.
   - Carries kernel monotonic sample timestamps separately from wall clock.

3. `ReplayEventSource` (fallback)
   - Unprivileged deterministic source for local tests/demos.
   - Used to prove correlation/loss/restart behavior when privileged loading is unavailable.

4. `BuildDaemonCustodyPlan` (local-only scaffold)
   - Validates root-owned daemon custody defaults for `/etc/ardur`, `/var/lib/ardur`, `/run/ardur`, and `/sys/fs/bpf/ardur`.
   - Rejects repository-controlled privileged paths when repository-root validation context is provided, plus daemon installation flags, daemon startup flags, permissive modes, and non-permission mode bits.
   - Returns a dry-run plan only. It does not create directories, bind sockets, pin maps, install service units, or start a privileged process.

5. `InspectDaemonCustodyPreflight` (read-only preflight)
   - Uses an injectable stat/realpath interface so tests do not depend on host `/etc`, `/var`, `/run`, or `/sys/fs/bpf`.
   - Reports structured findings with check name, path category, expected and observed owner/mode, verdict, and remediation text.
   - Distinguishes missing paths, symlinks, wrong type, wrong owner, wrong mode, non-permission mode bits, symlink-aware realpath escape, and repository-controlled privileged paths.
   - Treats setuid, setgid, and sticky bits as fail-closed custody failures in this scaffold. That strictness is intentional: inherited special bits must be investigated before a future privileged daemon trusts the path.
   - Does not repair paths, create directories, bind sockets, pin maps, install services, or start a daemon.

6. `DaemonProtocolRequest` / `DecodeDaemonProtocolRequest` (contract only)
   - Specifies newline-delimited deterministic JSON for `health`, `register_session`, `end_session`, and `session_status`.
   - Accepts unprivileged session/mission/trace identity plus observed root PID, PID namespace, cgroup id, event class, and bounded TTL.
   - Rejects unknown protocol versions, unknown event classes, missing session ids, unbounded TTLs, trailing non-JSON data, and client-supplied daemon-owned privileged path fields.
   - Applies the daemon-controlled field guard recursively and case-insensitively so future clients cannot hide daemon-owned filesystem authority or OS-observed peer identity inside metadata.
   - Keeps daemon-owned config/socket/bpffs paths and observed peer credentials out of client messages.

7. `AuthorizeObservedDaemonPeer` (contract only)
   - Authorizes daemon-observed local socket peer credentials against an explicit UID/GID allowlist.
   - Fails closed when the daemon has no allowlist, when PID observation is missing, or when the observed UID/GID does not match policy.
   - Does not retrieve peer credentials, open sockets, inspect process trees, or accept client-supplied identity.

8. `AuthorizeDaemonProtocolPeerFromAcceptedUnixConnection` (contract bridge)
   - Reads exactly one request from an already-accepted `*net.UnixConn` and decodes it via `DecodeDaemonProtocolRequest`.
   - Observes peer identity from the same connection via `ObserveLinuxUnixPeerCredentials` (Linux SO_PEERCRED seam).
   - Joins request and peer credentials through `AuthorizeDaemonProtocolPeer` for fail-closed authorization before any future handler runs.
   - Fails closed for malformed payloads, credential-observation failures, unsupported custody context, fabricated custody plans, or unauthorized peers.
   - Does not bind, listen, accept, install/start, or mutate privileged filesystem state.

9. `BuildDaemonAcceptLoopPlan` (dry-run contract only)
   - Validates the future accept-loop invariants before runtime implementation: valid daemon custody plan, explicit UID/GID allowlist, bounded request bytes, bounded read timeout, and bounded concurrency.
   - Records the sequence a later daemon must follow: read-only custody preflight, bind only the validated local socket path, accept bounded local connections, observe OS peer credentials, decode one bounded JSON-line request, authorize request+peer, then dispatch a validated protocol method.
   - Marks every step as not executed so the plan remains reviewable data, not daemon behavior.
   - Does not open, bind, listen on, accept, install, start, expose a daemon, manage session state, or perform live enforcement.

10. `AuthorizeDaemonProtocolPeer` (contract only)
   - Joins a validated daemon protocol request to daemon-observed peer credentials before future socket handling.
   - Requires the observation source to be explicit (`linux_so_peercred` today) and the observed socket path to match the validated dry-run daemon custody plan.
   - Fails closed for invalid protocol messages, missing/unsupported credential sources, socket-path mismatches, invalid custody plans, or unauthorized UID/GID policy.
   - Does not open, bind, listen on, accept, or inspect a socket; it does not perform the peer-credential syscall itself.

11. `ObserveLinuxUnixPeerCredentials` (Linux seam)
   - Reads SO_PEERCRED from an already-open `*net.UnixConn` and returns the daemon-owned `DaemonSocketPeerObservation` used by the handshake contract.
   - Requires the caller to supply the daemon-owned socket path and records `linux_so_peercred` as the explicit credential source.
   - Fails closed for a nil connection, missing socket path, SO_PEERCRED errors, or missing peer PID.
   - Does not open, bind, listen on, accept, install, start, or expose a daemon; Linux socketpair coverage exercises the retrieval seam without creating a public service.

12. `BuildLaunchWrapperSessionProof` (contract only)
   - Converts no-privilege launch-wrapper metadata for a generic CLI boundary into a validated daemon `register_session` request.
   - Seeds userspace correlation with the launched root PID, optional PID namespace, optional process-start monotonic timestamp, optional cgroup id, and launch wall-clock time.
   - Adds redacted handoff metadata, including command argv digest and argc, without storing raw argv, working directory text, executable paths, or environment values in the proof.
   - Rejects missing session id, empty command, missing root PID, missing start time, unbounded TTL, daemon-owned path or peer-credential fields, and raw command/path/environment handoff fields.
   - Does not execute a command, open sockets, retrieve SO_PEERCRED, start/install a daemon, mutate cgroups or BPF maps, or capture subprocess/file/network side effects.

## Generate the eBPF object

The generated object is committed with the package so ordinary unit tests do not require clang.
Regenerate only in a Linux dev image with clang/LLVM/libbpf headers available:

```bash
cd go
go generate ./pkg/kernelcapture
```

## Verification commands

Default tests are unprivileged and should pass on macOS and Linux:

```bash
cd go
go test ./pkg/kernelcapture -count=1
go test -race ./pkg/kernelcapture -count=1
GOOS=linux GOARCH=arm64 go test ./pkg/kernelcapture -c -o /tmp/kernelcapture-linux-arm64.test
```

The live eBPF smoke is intentionally gated because it needs a Linux kernel, BTF, tracefs/debugfs, BPF privileges, and enough memlock. In the local Podman-machine proof environment it was run with a rootful privileged container:

```bash
sudo podman run --rm --privileged --pid=host --ulimit memlock=-1:-1 \
  -v /sys/kernel/tracing:/sys/kernel/tracing:rw \
  -v /sys/kernel/debug:/sys/kernel/debug:rw \
  -v "$PWD/go:/workspace/go" \
  -w /workspace/go \
  -e ARDUR_RUN_EBPF_SMOKE=1 \
  ardur-ebpf-dev:fedora43 \
  go test -v ./pkg/kernelcapture -run TestLinuxEBPF -count=1
```

Rootless privileged containers can still fail if memlock cannot be raised or tracefs/debugfs are not visible. Treat that as environment evidence, not a product pass.

## Privileged boundary

This package does not install a daemon, persist maps, open a service, or manage system startup.
`BuildDaemonCustodyPlan` records the local-only future daemon boundary as validated data:

- config path: `/etc/ardur/kernelcapture-daemon.toml`, `0600`, root-owned
- state dir: `/var/lib/ardur/kernelcapture`, `0700`, root-owned
- runtime dir/socket: `/run/ardur/kernelcapture/control.sock`, socket `0600` or `0660`, root-owned
- bpffs dir/map: `/sys/fs/bpf/ardur/process_lifecycle_events`, root-owned

It rejects repository-controlled privileged paths when repository-root validation context is supplied, and it rejects any request to install or start a daemon in this scaffold slice. `InspectDaemonCustodyPreflight` adds the read-only on-disk inspection layer: symlink-aware realpath checks, owner/mode/type observations, and structured remediation text. `AuthorizeObservedDaemonPeer` adds the fail-closed local-client authorization contract for the future socket server: peer identity must be observed by daemon-owned socket code and matched against an explicit UID/GID allowlist, never supplied by JSON clients. `AuthorizeDaemonProtocolPeer` adds the next no-mutation handshake contract: a decoded protocol request is not considered ready for handling until it is paired with daemon-observed peer credentials from an explicit OS source and the observed socket path matches the dry-run custody plan. `ObserveLinuxUnixPeerCredentials` is the Linux SO_PEERCRED retrieval seam for an already-open Unix connection; it still does not create a listener or accept loop. `BuildDaemonAcceptLoopPlan` records the future accept-loop invariants as dry-run data: a valid custody plan, explicit peer allowlist, bounded request bytes, bounded read timeout, bounded concurrency, and not-yet-executed steps for preflight, bind, accept, peer observation, request decoding, authorization, and dispatch. `BuildLaunchWrapperSessionProof` records how a future `ardur run -- <cli>` launch wrapper can hand a generic CLI session id and root process identity to the daemon protocol without claiming command execution or side-effect capture. The scaffold records the future daemon-boundary requirement that repo/mission config must not select privileged map paths; integration with mission config remains future work. For the future daemon path:

- `pinnedMapPath` must come from daemon-owned privileged config.
- Repository / mission config must not control privileged map-path selection.
- Cgroup filtering must only be enabled after daemon-owned code has inserted at
  least one non-zero cgroup id into the allowlist map.
- Privileged daemon deployments should use:
  - root-owned daemon config
  - root-owned restrictive bpffs namespace/path
  - explicit producer ownership/version checks before trusting samples

## Concurrency contract

- `Correlator` is goroutine-safe and supports concurrent receipt registration and event correlation.
- Race-safety is covered by `go test -race ./pkg/kernelcapture`.

## Current MVP claim boundary

Allowed claim after the gated smoke passes:

Ardur has a local Linux eBPF process-lifecycle proof with optional daemon-populated cgroup allowlist filtering, plus a no-mutation daemon custody preflight inspector, fail-closed local peer authorization/handshake contracts, a Linux SO_PEERCRED retrieval seam for already-owned Unix connections, a dry-run accept-loop invariant plan, a local JSON-line protocol contract scaffold for the future launch-wrapper-to-daemon boundary, and a no-privilege launch-wrapper session proof seam that turns generic CLI boundary metadata into a validated `register_session` request plus root-process correlator seed.

Not claimed yet:

- production daemon readiness
- daemon installation or startup
- socket server/listener implementation
- daemon accept-loop wiring around SO_PEERCRED observations
- daemon-created per-session cgroups
- universal CLI capture
- file/network/privilege side-effect capture
- macOS/Windows kernel capture
- unprivileged/no-install eBPF support
