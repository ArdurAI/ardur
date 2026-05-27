"""Tests for the content safety scanner."""

from __future__ import annotations

import pytest
from vibap.content_safety import (
    ContentSafetyConfig,
    ContentSafetyResult,
    RULES,
    scan,
    scan_string,
)


class TestDetection:
    def test_credit_card_visa(self):
        result = scan_string("card: 4111111111111111")
        assert any(a.rule_name == "credit_card" for a in result.alerts)

    def test_credit_card_mastercard(self):
        result = scan_string("card: 5555555555554444")
        assert any(a.rule_name == "credit_card" for a in result.alerts)

    def test_credit_card_amex(self):
        result = scan_string("card: 378282246310005")
        assert any(a.rule_name == "credit_card" for a in result.alerts)

    def test_credit_card_discover(self):
        result = scan_string("card: 6011111111111117")
        assert any(a.rule_name == "credit_card" for a in result.alerts)

    def test_ssn_with_dashes(self):
        result = scan_string("SSN: 123-45-6789")
        assert any(a.rule_name == "ssn" for a in result.alerts)

    def test_ssn_with_spaces(self):
        result = scan_string("SSN: 123 45 6789")
        assert any(a.rule_name == "ssn" for a in result.alerts)

    def test_api_key_openai(self):
        result = scan_string("token: sk-proj-abcdefghijklmnopqrstuvwxyz123456")
        assert any(a.rule_name == "api_key" for a in result.alerts)

    def test_api_key_github_classic(self):
        result = scan_string("export GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz1234567890")
        assert any(a.rule_name == "api_key" for a in result.alerts)

    def test_api_key_aws(self):
        result = scan_string("AWS key: AKIAIOSFODNN7EXAMPLE")
        assert any(a.rule_name == "api_key" for a in result.alerts)

    def test_email(self):
        result = scan_string("contact: user@example.com")
        assert any(a.rule_name == "email" for a in result.alerts)

    def test_email_with_subdomain(self):
        result = scan_string("reach out to admin@mail.example.co.uk")
        assert any(a.rule_name == "email" for a in result.alerts)


class TestFalsePositives:
    def test_random_16_digit_number_not_card(self):
        result = scan_string("id: 1234567890123456")
        assert not any(a.rule_name == "credit_card" for a in result.alerts)

    def test_short_number_ignored(self):
        result = scan_string("code: 12345")
        assert len(result.alerts) == 0

    def test_non_sensitive_text(self):
        result = scan_string("the quick brown fox jumps over the lazy dog")
        assert len(result.alerts) == 0

    def test_url_not_email(self):
        result = scan_string("visit https://example.com/path")
        assert not any(a.rule_name == "email" for a in result.alerts)


class TestConfigModes:
    def test_deny_mode_sets_unsafe(self):
        config = ContentSafetyConfig(mode="deny")
        result = scan_string("card: 4111111111111111", config)
        assert not result.safe

    def test_warn_mode_still_safe(self):
        config = ContentSafetyConfig(mode="warn")
        result = scan_string("card: 4111111111111111", config)
        assert result.safe
        assert len(result.alerts) > 0

    def test_redact_mode_sets_unsafe_and_produces_redacted(self):
        config = ContentSafetyConfig(mode="redact")
        result = scan_string("use card 4111111111111111 for payment", config)
        assert not result.safe
        assert result.redacted_text is not None
        assert "4111111111111111" not in result.redacted_text
        assert "[REDACTED]" in result.redacted_text

    def test_per_category_override(self):
        config = ContentSafetyConfig(
            mode="warn",
            per_category={"pii": "deny", "credential": "redact"},
        )
        result_cc = scan_string("4111111111111111", config)
        assert not result_cc.safe  # pii is deny

        result_token = scan_string("sk-proj-abcdefghijklmnopqrstuvwxyz123456", config)
        assert not result_token.safe  # credential is redact
        assert result_token.redacted_text is not None

        result_email = scan_string("user@example.com", config)
        assert result_email.safe  # contact falls back to warn


class TestDisabled:
    def test_disabled_config_skips_all_checks(self):
        config = ContentSafetyConfig(enabled=False)
        result = scan_string("card: 4111111111111111, SSN: 123-45-6789", config)
        assert result.safe
        assert len(result.alerts) == 0

    def test_empty_string(self):
        result = scan_string("", ContentSafetyConfig(mode="deny"))
        assert result.safe
        assert len(result.alerts) == 0


class TestRecursiveScan:
    def test_scan_dict_finds_nested_values(self):
        config = ContentSafetyConfig(mode="deny")
        result = scan(
            {"user": {"name": "test", "contact": "user@example.com"}},
            config,
        )
        assert not result.safe
        assert any(a.rule_name == "email" for a in result.alerts)

    def test_scan_list_finds_items(self):
        config = ContentSafetyConfig(mode="deny")
        result = scan(
            ["read", "file", "api_key=sk-proj-abcdefghijklmnopqrstuvwxyz123456"],
            config,
        )
        assert not result.safe

    def test_non_string_scalars_ignored(self):
        config = ContentSafetyConfig(mode="deny")
        result = scan({"count": 42, "active": True, "value": None}, config)
        assert result.safe
        assert len(result.alerts) == 0

    def test_deeply_nested_bounded(self):
        config = ContentSafetyConfig(mode="deny")
        data = {"a": 1}
        for _ in range(30):
            data = {"nested": data}
        result = scan(data, config)
        assert result.safe  # depth limit hit, no exception


class TestRedaction:
    def test_multiple_matches_redacted(self):
        config = ContentSafetyConfig(mode="redact")
        result = scan_string(
            "email user@example.com and backup admin@test.org",
            config,
        )
        assert result.redacted_text is not None
        assert "user@example.com" not in result.redacted_text
        assert "admin@test.org" not in result.redacted_text
        assert result.redacted_text.count("[REDACTED]") == 2

    def test_no_matches_redacted_is_none(self):
        config = ContentSafetyConfig(mode="redact")
        result = scan_string("clean text here", config)
        assert result.safe
        assert result.redacted_text is None


class TestRULES:
    def test_all_rules_have_unique_names(self):
        names = [r.name for r in RULES]
        assert len(names) == len(set(names))

    def test_all_rules_compile(self):
        for rule in RULES:
            assert rule.pattern is not None
            assert isinstance(rule.category, str)
            assert rule.name


class TestResultProperties:
    def test_categories_set(self):
        config = ContentSafetyConfig(mode="warn")
        result = scan_string("4111111111111111 user@example.com", config)
        assert "pii" in result.categories
        assert "contact" in result.categories

    def test_default_config(self):
        config = ContentSafetyConfig()
        assert config.mode == "warn"
        assert config.enabled
        assert config.mode_for("pii") == "warn"
