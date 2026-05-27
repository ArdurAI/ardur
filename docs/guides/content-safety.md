# Content Safety Plugin

The content safety plugin scans tool-call inputs and outputs for sensitive data
before they reach an external service or are written to a receipt. It is
deterministic, regex-based, and has no LLM dependency — it runs locally and
adds microseconds of latency per scan.

Source: [`python/vibap/content_safety.py`](../../python/vibap/content_safety.py).

## What it detects

| Category | Pattern | Example |
|----------|---------|---------|
| `credit_card` | Visa, Mastercard, Amex, Discover PANs | `4111-1111-1111-1111` |
| `ssn` | US Social Security numbers (with dashes or spaces) | `123-45-6789` |
| `email` | RFC 5322 email addresses | `user@example.com` |
| `api_key` | OpenAI, GitHub classic, AWS access keys | `sk-proj-abcdef...` |

## Modes

Each category can be configured independently with one of three modes:

| Mode | Behavior |
|------|----------|
| `deny` | Block the action. Set `safe = False` on the scan result. |
| `redact` | Replace matched text with `[REDACTED:<category>]` but do not block. Sets `safe = False` and returns the redacted string in `redacted_content`. |
| `warn` | Log and continue. The action proceeds; the alert is recorded in metrics and the scan result. |
| (omitted) | Skip detection for that category entirely. |

The default config enables all four categories in `warn` mode.

## API

```python
from vibap.content_safety import ContentSafetyConfig, scan, scan_string

# Per-category overrides
config = ContentSafetyConfig(
    enabled=True,
    modes={"credit_card": "deny", "api_key": "redact"},
)

# Scan a raw string
result = scan_string("sk-proj-abc123...", config)
# result.safe        -> False (api_key is in redact mode)
# result.alerts      -> [ContentSafetyAlert(category="api_key", mode="redact", ...)]
# result.redacted    -> "[REDACTED:api_key]"

# Scan a nested dict (e.g., a tool-call arguments payload)
result = scan({"input": "my ssn is 123-45-6789"}, config)
# Recursively scans all string values up to depth 10.
```

### `ContentSafetyConfig`

```python
@dataclass
class ContentSafetyConfig:
    enabled: bool = True
    modes: dict[str, str] = field(default_factory=lambda: {
        "credit_card": "warn",
        "ssn": "warn",
        "email": "warn",
        "api_key": "warn",
    })
```

### `ContentSafetyResult`

```python
@dataclass
class ContentSafetyResult:
    safe: bool                  # False if any deny/redact-mode rule matched
    alerts: list[ContentSafetyAlert]
    redacted_content: str | None  # Redacted string (redact mode only)
    categories: set[str]         # Categories that fired
```

## Integration points

- **MCP Gateway** — runs pre-scan on `tools/call` arguments and post-scan on
  tool output before forwarding to the client.
- **Governance Proxy** — can be plugged into tool-call evaluation as a
  pre-flight check via `ContentSafetyConfig` passed through the MCP gateway
  config or the proxy session context.

## Metrics

Alerts are emitted through `ardur_content_safety_alerts_total` with labels
`category` and `mode`:

```
ardur_content_safety_alerts_total{category="api_key",mode="deny"} 3
ardur_content_safety_alerts_total{category="credit_card",mode="warn"} 1
```

Source: [`python/vibap/metrics.py`](../../python/vibap/metrics.py).

## Design choices

- **No LLM dependency.** All detection is regex-based. This keeps latency
  predictable (microseconds, not seconds), avoids calling an external service
  with the very secrets you're trying to protect, and makes the detector
  auditable — every rule is a visible regex.
- **Recursive scanning with depth bound.** Dicts and lists are scanned
  recursively up to depth 10 to catch secrets nested inside structured
  tool-call arguments. Scalars (int, float, bool, None) are skipped.
- **Fail-open on scan errors.** If the scanner itself raises (e.g. an
  unexpected type), the result defaults to `safe = True` — scanning is a
  defense-in-depth layer, not a hard security boundary.

## Caveats

This is a **heuristic defense-in-depth layer**, not a cryptographic guarantee:

- Regex-based detection has both false positives and false negatives.
- A sufficiently obfuscated secret (e.g. base64-encoded, split across
  multiple fields) will not be detected.
- This layer complements, but does not replace, proper secret management
  (environment variables, secret stores, SPIFFE-issued identities).
