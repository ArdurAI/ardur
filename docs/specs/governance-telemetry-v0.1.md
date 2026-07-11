# Ardur Governance Telemetry v0.1

Status: implementation profile.

This profile projects a verified Ardur Execution Receipt chain into redacted
local JSONL and OpenTelemetry Protocol (OTLP) trace and log records. Export is
detached from the governance decision path and does not mutate signed receipts.

## Trust boundary

An exporter MUST verify every receipt signature, the full parent-hash chain,
lineage identifiers, and monotonic receipt ordering before it emits an event.
Unverified claims MUST NOT be exported as Ardur governance telemetry.

The local event binds:

- receipt ID and signed parent receipt hash;
- trace, actor, verifier, and grant identifiers;
- tri-state verdict and `PERMIT`, `DENY`, or `ERROR` projection;
- signed policy backend, decision, and optional stable `rule_id`;
- signed reason code, budget state, and risk classification;
- signed invocation and arguments digests; and
- the verified source-journal digest.

## Redaction

The default export never includes prompts, raw tool arguments, raw targets,
file paths, policy-reason prose, model inputs or outputs, bearer credentials,
or signing material. It exports signed digests and bounded classifications
instead. String identifiers pass through the offline verifier's credential
redactor and the shareable-artifact local-path redactor.

This is a conservative export contract, not a claim that arbitrary telemetry
backends are safe for sensitive data. Operators remain responsible for
collector authentication, transport security, retention, access control, and
regional data handling.

## OTLP mapping

The exporter uses OTLP/HTTP JSON and sends `ExportTraceServiceRequest` and
`ExportLogsServiceRequest` payloads to `/v1/traces` and `/v1/logs`.

- Instrumentation scope: `io.ardur.governance`
- Event name: `ardur.governance.decision`
- Application attributes: `ardur.*`
- OTLP trace ID: first 16 bytes of SHA-256 over the signed Ardur trace ID
- OTLP span ID: first 8 bytes of SHA-256 over the signed receipt ID
- Parent span ID: the previous verified receipt's span ID when the signed
  parent receipt hash is non-null

Policy denial is a successful governance outcome. The exporter records the
decision as an attribute and does not automatically mark the span as an OTLP
error. `ERROR` is reserved for Ardur's insufficient-evidence projection.

## Delivery boundary

The one-shot CLI does not retry. OTLP collectors can acknowledge success,
partial success, or failure; partial rejection fails the command. Re-running
may create duplicate telemetry, so downstream systems SHOULD deduplicate on
`ardur.receipt.id`.

Plain HTTP endpoints are accepted only for loopback collectors. Remote
collectors require HTTPS. Standard `OTEL_EXPORTER_OTLP_HEADERS` and
signal-specific header environment variables may supply authentication without
placing credentials in command-line arguments.

## Primary sources

- OpenTelemetry Protocol 1.10.0:
  <https://opentelemetry.io/docs/specs/otlp/>
- OpenTelemetry semantic-convention naming:
  <https://opentelemetry.io/docs/specs/semconv/general/naming/>
- Official OTLP JSON request examples:
  <https://github.com/open-telemetry/opentelemetry-proto/tree/v1.10.0/examples>
