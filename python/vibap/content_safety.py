"""Pluggable content safety scanner for tool inputs and outputs.

No external LLM dependency — deterministic regex + heuristics.
Detects credit cards, SSNs, emails, API keys, and other sensitive patterns.
Configurable per-category modes: deny, redact, or warn.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# ── Patterns ─────────────────────────────────────────────────────────

_CREDIT_CARD_RE = re.compile(
    r"\b(?:4[0-9]{12}(?:[0-9]{3})?"  # Visa
    r"|5[1-5][0-9]{14}"  # MasterCard
    r"|3[47][0-9]{13}"  # AmEx
    r"|6(?:011|5[0-9]{2})[0-9]{12}"  # Discover
    r")\b"
)

_SSN_RE = re.compile(
    r"\b(?!000|666|9\d{2})"  # No 000, 666, or 900-999 area
    r"\d{3}"  # Area
    r"[- ]?"
    r"(?!00)\d{2}"  # Group (no 00)
    r"[- ]?"
    r"(?!0000)\d{4}\b"  # Serial (no 0000)
)

_EMAIL_RE = re.compile(
    r"\b[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+"
    r"@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\b"
)

_API_KEY_RE = re.compile(
    r"(?:sk-[a-zA-Z0-9\\-]{20,}"  # OpenAI
    r"|ghp_[a-zA-Z0-9]{36}"  # GitHub classic
    r"|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}"  # GitHub fine-grained
    r"|AKIA[0-9A-Z]{16}"  # AWS access key
    r"|AIza[0-9A-Za-z\\-_]{35}"  # Google API
    r"|xox[baprs]-[a-zA-Z0-9-]+"  # Slack
    r")"
)


@dataclass
class ContentSafetyRule:
    """A single detection pattern with metadata."""

    name: str
    pattern: re.Pattern
    category: str  # "pii", "credential", "contact"
    description: str = ""


RULES: list[ContentSafetyRule] = [
    ContentSafetyRule(
        name="credit_card",
        pattern=_CREDIT_CARD_RE,
        category="pii",
        description="Credit card number",
    ),
    ContentSafetyRule(
        name="ssn",
        pattern=_SSN_RE,
        category="pii",
        description="US Social Security Number",
    ),
    ContentSafetyRule(
        name="api_key",
        pattern=_API_KEY_RE,
        category="credential",
        description="API key or access token",
    ),
    ContentSafetyRule(
        name="email",
        pattern=_EMAIL_RE,
        category="contact",
        description="Email address",
    ),
]


@dataclass
class ContentSafetyConfig:
    """Scanner configuration."""

    mode: str = "warn"  # "deny" | "redact" | "warn"
    per_category: dict[str, str] = field(default_factory=dict)
    enabled: bool = True

    def mode_for(self, category: str) -> str:
        return self.per_category.get(category, self.mode)


@dataclass
class ContentSafetyAlert:
    """Single detection result."""

    rule_name: str
    category: str
    match_text: str
    start: int
    end: int


@dataclass
class ContentSafetyResult:
    """Result of scanning content."""

    alerts: list[ContentSafetyAlert] = field(default_factory=list)
    redacted_text: str | None = None
    safe: bool = True

    @property
    def categories(self) -> set[str]:
        return {a.category for a in self.alerts}


def scan_string(
    text: str,
    config: ContentSafetyConfig | None = None,
) -> ContentSafetyResult:
    """Scan a single string value for sensitive content."""
    if config is None:
        config = ContentSafetyConfig()
    if not config.enabled or not text:
        return ContentSafetyResult()

    alerts: list[ContentSafetyAlert] = []
    for rule in RULES:
        for m in rule.pattern.finditer(text):
            alerts.append(
                ContentSafetyAlert(
                    rule_name=rule.name,
                    category=rule.category,
                    match_text=m.group(),
                    start=m.start(),
                    end=m.end(),
                )
            )

    safe = True
    redacted = None
    needs_redact = False

    for alert in alerts:
        mode = config.mode_for(alert.category)
        if mode in ("deny", "redact"):
            safe = False
        if mode == "redact":
            needs_redact = True

    if needs_redact:
        redacted = _redact_string(text, alerts)

    return ContentSafetyResult(alerts=alerts, redacted_text=redacted, safe=safe)


def scan(
    data: Any,
    config: ContentSafetyConfig | None = None,
    _depth: int = 0,
) -> ContentSafetyResult:
    """Recursively scan structured data (dicts, lists, strings) for sensitive content."""
    if config is None:
        config = ContentSafetyConfig()
    if not config.enabled:
        return ContentSafetyResult()
    if _depth > 20:
        return ContentSafetyResult()

    all_alerts: list[ContentSafetyAlert] = []
    safe = True

    if isinstance(data, str):
        return scan_string(data, config)
    if isinstance(data, dict):
        for _key, value in data.items():
            sub = scan(value, config, _depth + 1)
            all_alerts.extend(sub.alerts)
            if not sub.safe:
                safe = False
    elif isinstance(data, (list, tuple)):
        for item in data:
            sub = scan(item, config, _depth + 1)
            all_alerts.extend(sub.alerts)
            if not sub.safe:
                safe = False
    # Non-string scalars (int, float, bool, None) are never sensitive.

    return ContentSafetyResult(alerts=all_alerts, safe=safe)


def _redact_string(text: str, alerts: list[ContentSafetyAlert]) -> str:
    """Replace matched regions with [REDACTED] markers."""
    if not alerts:
        return text
    sorted_alerts = sorted(alerts, key=lambda a: a.start)
    parts: list[str] = []
    pos = 0
    for alert in sorted_alerts:
        if alert.start < pos:
            continue  # overlapping; skip
        parts.append(text[pos : alert.start])
        parts.append("[REDACTED]")
        pos = alert.end
    parts.append(text[pos:])
    return "".join(parts)
