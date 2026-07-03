// EndpointSecurityClient.swift — Endpoint Security client scaffold
// (Epic A #63, Slice 2 remainder).
//
// This is a SCAFFOLD, not a built artifact: nothing in this repository's Go
// build (go build/go test/go vet, none of which touch this file) or CI
// invokes swiftc against it. It exists to pin down the exact shape a real
// client will take once Apple grants
// com.apple.developer.endpoint-security.client for the ardur-kernelcaptured
// signing identity (tracking issue referenced from the PR that introduced
// this file) — without shipping cgo bindings that could never be exercised
// or tested in this environment either way. See
// go/pkg/kernelcapture/es_client_darwin.go's header comment for the fuller
// rationale and the Go-side interface (ESClient) this is expected to satisfy
// once wired up.
//
// Event shape parity: ArdurProcessEvent's fields deliberately mirror Go's
// kernelcapture.ProcessEvent (types.go) — PID/PPID/comm/exit_code/observed
// timestamp — not es_message_t's native shape, so that whatever hand-off
// mechanism eventually connects this extension to the ardur-kernelcaptured
// daemon (a local Unix socket is the natural choice, matching the pattern
// the daemon already uses for its control-plane socket) can carry a payload
// the daemon-side decoder can consume with no macOS-specific event shape of
// its own.
//
// NOT in this scaffold (left for the implementation that follows entitlement
// grant):
//   - The actual hand-off transport from this extension process to
//     ardur-kernelcaptured (candidate: a local Unix socket, written by this
//     extension, read by a real es_client_darwin.go NewESClient
//     implementation).
//   - Extension activation/lifecycle via SystemExtensions.framework
//     (OSSystemExtensionRequest) from a host app — that lives outside this
//     package entirely.
//   - Author-time entitlement/provisioning-profile embedding (requires an
//     Apple Developer account entry once the request is approved).

import EndpointSecurity
import Foundation

/// Mirrors go/pkg/kernelcapture/types.go's ProcessEvent — see this file's
/// header comment for why the shapes are kept in lockstep.
struct ArdurProcessEvent {
	enum Kind: String {
		case exec
		case exit
	}

	let kind: Kind
	let pid: pid_t
	let ppid: pid_t
	let comm: String
	let exitCode: Int32
	let observedAtNanoseconds: UInt64
}

/// esStringToken decodes an es_string_token_t (a length-prefixed, not
/// necessarily NUL-terminated C string view into ES's own buffer) into a
/// Swift String.
private func esStringToken(_ token: es_string_token_t) -> String {
	guard let data = token.data, token.length > 0 else { return "" }
	return String(decoding: UnsafeBufferPointer(start: data, count: token.length).map { UInt8(bitPattern: $0) }, as: UTF8.self)
}

/// ArdurEndpointSecurityExtension is the NSExtensionPrincipalClass named in
/// Info.plist. A real implementation subscribes to NOTIFY_EXEC/NOTIFY_EXIT
/// (matching the Linux eBPF tracepoint consumer's exec/exit scope) and, once
/// the entitlement is granted, could extend to AUTH_* events for real-time
/// enforcement — the macOS analogue of process_guard.bpf.c's BPF-LSM hooks.
final class ArdurEndpointSecurityExtension: NSObject {
	private var client: OpaquePointer?

	/// start subscribes to the process-lifecycle event set. Returns false
	/// (and logs the reason) if es_new_client fails — which it always will
	/// today, since the required entitlement has not been granted. Apple's
	/// es_new_client itself is the enforcement point for the entitlement
	/// check; there is nothing this scaffold can do to bypass that, by
	/// design.
	func start() -> Bool {
		var newClient: OpaquePointer?
		let result = es_new_client(&newClient) { _, message in
			ArdurEndpointSecurityExtension.handle(message: message)
		}
		guard result == ES_NEW_CLIENT_RESULT_SUCCESS, let created = newClient else {
			NSLog("ardur-endpoint-security: es_new_client failed: \(result.rawValue) " +
				"(expected until com.apple.developer.endpoint-security.client is granted)")
			return false
		}
		self.client = created

		let events: [es_event_type_t] = [ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_EXIT]
		let subscribeResult = es_subscribe(created, events, UInt32(events.count))
		if subscribeResult != ES_RETURN_SUCCESS {
			NSLog("ardur-endpoint-security: es_subscribe failed: \(subscribeResult.rawValue)")
			return false
		}
		return true
	}

	func stop() {
		if let client {
			es_delete_client(client)
		}
		client = nil
	}

	/// handle projects an es_message_t into ArdurProcessEvent. The real
	/// hand-off to ardur-kernelcaptured (see this file's header comment) is
	/// not implemented in this scaffold.
	private static func handle(message: UnsafePointer<es_message_t>) {
		let msg = message.pointee
		switch msg.event_type {
		case ES_EVENT_TYPE_NOTIFY_EXEC:
			let target = msg.event.exec.target.pointee
			_ = ArdurProcessEvent(
				kind: .exec,
				pid: audit_token_to_pid(target.audit_token),
				ppid: audit_token_to_pid(target.parent_audit_token),
				comm: esStringToken(target.executable.pointee.path),
				exitCode: 0,
				observedAtNanoseconds: UInt64(msg.time.tv_sec) * 1_000_000_000 + UInt64(msg.time.tv_nsec)
			)
		case ES_EVENT_TYPE_NOTIFY_EXIT:
			let target = msg.process.pointee
			_ = ArdurProcessEvent(
				kind: .exit,
				pid: audit_token_to_pid(target.audit_token),
				ppid: audit_token_to_pid(target.parent_audit_token),
				comm: "",
				exitCode: msg.event.exit.stat,
				observedAtNanoseconds: UInt64(msg.time.tv_sec) * 1_000_000_000 + UInt64(msg.time.tv_nsec)
			)
		default:
			break
		}
		// TODO(#es-hand-off): forward the projected event to
		// ardur-kernelcaptured once the transport (see header comment) is
		// designed. Discarded here — this scaffold only proves the
		// subscribe+decode shape compiles against the real ES headers.
	}
}
