from __future__ import annotations

import base64
import json
import time
import urllib.error
import zlib
from pathlib import Path

import jwt
import pytest

import vibap.mission as mission_module
from vibap.passport import MissionPassport, issue_passport
from vibap.proxy import Decision

from conftest import v01_required_md_extras


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _decode_b64url_json(segment: str) -> dict[str, object]:
    padded = segment + ("=" * (-len(segment) % 4))
    return json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))


def _tamper_jwt_payload(token: str, updates: dict[str, object]) -> str:
    header, payload, signature = token.split(".")
    claims = _decode_b64url_json(payload)
    claims.update(updates)
    tampered_payload = _b64url(
        json.dumps(claims, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )
    return ".".join([header, tampered_payload, signature])


def _status_list_token(private_key, *, idx: int, revoked: bool) -> str:
    size_bits = max(8, idx + 1)
    raw = bytearray((size_bits + 7) // 8)
    if revoked:
        raw[idx // 8] |= 1 << (7 - (idx % 8))
    now = int(time.time())
    claims = {
        "iss": "status-authority",
        "sub": "status-list",
        "iat": now,
        "exp": now + 300,
        "status_list": {
            "bits": 1,
            "lst": _b64url(zlib.compress(bytes(raw))),
        },
    }
    return jwt.encode(claims, private_key, algorithm="ES256")


def _issue_md(private_key, *, mission_id: str, revocation_ref: str) -> str:
    mission = MissionPassport(
        agent_id="md-authority",
        mission_id=mission_id,
        mission="authoritative report mission",
        allowed_tools=["read_file"],
        forbidden_tools=["delete_file"],
        resource_scope=["/allowed/*"],
        max_tool_calls=3,
        max_duration_s=120,
        delegation_allowed=False,
        max_delegation_depth=0,
    )
    return issue_passport(
        mission,
        private_key,
        ttl_s=120,
        extra_claims=v01_required_md_extras(
            mission_id=mission_id,
            revocation_ref=revocation_ref,
        ),
    )


def _issue_dg(private_key, *, mission_ref: dict[str, str] | str) -> str:
    dg = MissionPassport(
        agent_id="delegate-agent",
        mission="delegated task",
        allowed_tools=["read_file", "delete_file"],
        forbidden_tools=[],
        resource_scope=["/wide/*"],
        max_tool_calls=20,
        max_duration_s=120,
        delegation_allowed=False,
        max_delegation_depth=0,
    )
    return issue_passport(
        dg, private_key, ttl_s=120, extra_claims={"mission_ref": mission_ref}
    )


class _Response:
    def __init__(self, body: str | bytes) -> None:
        self._body = body.encode("utf-8") if isinstance(body, str) else body

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            return self._body
        return self._body[:size]

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False


@pytest.fixture(autouse=True)
def _isolate_mission_fetch_binding(monkeypatch):
    original_urlopen = mission_module.urllib.request.urlopen
    monkeypatch.setattr(mission_module, "urlopen", original_urlopen)
    yield
    monkeypatch.setattr(mission_module, "urlopen", original_urlopen)


def _install_fetch_map(monkeypatch, mapping: dict[str, str | Exception]) -> list[str]:
    calls: list[str] = []

    def fake_urlopen(request, timeout=0, context=None):  # noqa: ANN001, ARG001
        url = request.full_url if hasattr(request, "full_url") else str(request)
        calls.append(url)
        value = mapping[url]
        if isinstance(value, Exception):
            raise value
        return _Response(value)

    monkeypatch.setattr(mission_module, "urlopen", fake_urlopen)
    return calls


def _receipt_entries(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def test_proxy_verifies_md_and_emits_receipt(
    proxy, private_key, public_key, monkeypatch
):
    mission_id = "urn:ardur:mission:test:permit"
    md_url = "https://issuer.example/md/permit.jwt"
    status_url = "https://issuer.example/status/permit.jwt"
    revocation_ref = status_url + "#idx=4"
    md_token = _issue_md(
        private_key, mission_id=mission_id, revocation_ref=revocation_ref
    )
    md = mission_module.load_mission_declaration(md_token, public_key)
    dg_token = _issue_dg(
        private_key,
        mission_ref={
            "uri": md_url,
            "mission_id": mission_id,
            "mission_digest": md.payload_digest,
        },
    )
    _install_fetch_map(
        monkeypatch,
        {
            md_url: md_token,
            status_url: _status_list_token(private_key, idx=4, revoked=False),
        },
    )

    session = proxy.start_session(dg_token)
    decision, reason = proxy.evaluate_tool_call(
        session,
        "read_file",
        {"path": "/allowed/report.txt", "operator_id": "op-1"},
    )

    assert decision == Decision.PERMIT
    assert reason == "within scope"
    receipts = _receipt_entries(proxy.receipts_log_path)
    assert len(receipts) == 1
    assert receipts[0]["grant_id"] == session.jti
    assert receipts[0]["verdict"] == "compliant"


def test_md_policy_is_authoritative_over_dg_scope(
    proxy, private_key, public_key, monkeypatch
):
    mission_id = "urn:ardur:mission:test:scope"
    md_url = "https://issuer.example/md/scope.jwt"
    status_url = "https://issuer.example/status/scope.jwt"
    md_token = _issue_md(
        private_key, mission_id=mission_id, revocation_ref=status_url + "#idx=1"
    )
    md = mission_module.load_mission_declaration(md_token, public_key)
    dg_token = _issue_dg(
        private_key,
        mission_ref={
            "uri": md_url,
            "mission_id": mission_id,
            "mission_digest": md.payload_digest,
        },
    )
    _install_fetch_map(
        monkeypatch,
        {
            md_url: md_token,
            status_url: _status_list_token(private_key, idx=1, revoked=False),
        },
    )

    session = proxy.start_session(dg_token)
    decision, reason = proxy.evaluate_tool_call(
        session, "read_file", {"path": "/wide/report.txt"}
    )

    assert decision == Decision.DENY
    assert "outside resource_scope" in reason


def test_revoked_md_returns_violation(proxy, private_key, public_key, monkeypatch):
    mission_id = "urn:ardur:mission:test:revoked"
    md_url = "https://issuer.example/md/revoked.jwt"
    status_url = "https://issuer.example/status/revoked.jwt"
    md_token = _issue_md(
        private_key, mission_id=mission_id, revocation_ref=status_url + "#idx=7"
    )
    md = mission_module.load_mission_declaration(md_token, public_key)
    dg_token = _issue_dg(
        private_key,
        mission_ref={
            "uri": md_url,
            "mission_id": mission_id,
            "mission_digest": md.payload_digest,
        },
    )
    _install_fetch_map(
        monkeypatch,
        {
            md_url: md_token,
            status_url: _status_list_token(private_key, idx=7, revoked=True),
        },
    )

    session = proxy.start_session(dg_token)
    decision, reason = proxy.evaluate_tool_call(
        session, "read_file", {"path": "/allowed/report.txt"}
    )

    assert decision == Decision.VIOLATION
    assert reason == "revoked"


def test_tampered_md_returns_chain_invalid(
    tmp_path, private_key, public_key, session_keys_dir, monkeypatch
):
    from vibap.proxy import GovernanceProxy

    proxy = GovernanceProxy(
        log_path=tmp_path / "tampered_log.jsonl",
        state_dir=tmp_path / "tampered_state",
        public_key=public_key,
        keys_dir=session_keys_dir,
    )
    mission_id = "urn:ardur:mission:test:tampered"
    md_url = "https://issuer.example/md/tampered.jwt"
    status_url = "https://issuer.example/status/tampered.jwt"
    md_token = _issue_md(
        private_key, mission_id=mission_id, revocation_ref=status_url + "#idx=2"
    )
    md = mission_module.load_mission_declaration(md_token, public_key)
    tampered = _tamper_jwt_payload(md_token, {"mission": "tampered mission"})
    dg_token = _issue_dg(
        private_key,
        mission_ref={
            "uri": md_url,
            "mission_id": mission_id,
            "mission_digest": md.payload_digest,
        },
    )
    _install_fetch_map(
        monkeypatch,
        {
            md_url: tampered,
            status_url: _status_list_token(private_key, idx=2, revoked=False),
        },
    )

    session = proxy.start_session(dg_token)
    decision, reason = proxy.evaluate_tool_call(
        session, "read_file", {"path": "/allowed/report.txt"}
    )

    assert decision == Decision.VIOLATION
    assert reason == "chain_invalid"


def test_status_list_network_error_fails_closed(
    proxy, private_key, public_key, monkeypatch
):
    mission_id = "urn:ardur:mission:test:network"
    md_url = "https://issuer.example/md/network.jwt"
    status_url = "https://issuer.example/status/network.jwt"
    md_token = _issue_md(
        private_key, mission_id=mission_id, revocation_ref=status_url + "#idx=5"
    )
    md = mission_module.load_mission_declaration(md_token, public_key)
    dg_token = _issue_dg(
        private_key,
        mission_ref={
            "uri": md_url,
            "mission_id": mission_id,
            "mission_digest": md.payload_digest,
        },
    )
    _install_fetch_map(
        monkeypatch,
        {
            md_url: md_token,
            status_url: urllib.error.URLError("boom"),
        },
    )

    session = proxy.start_session(dg_token)
    decision, reason = proxy.evaluate_tool_call(
        session, "read_file", {"path": "/allowed/report.txt"}
    )

    assert decision == Decision.INSUFFICIENT_EVIDENCE
    assert reason == "revocation_unavailable"


def test_oversized_status_list_rejected(proxy, private_key, public_key, monkeypatch):
    mission_id = "urn:ardur:mission:test:oversized-status-list"
    md_url = "https://issuer.example/md/oversized.jwt"
    status_url = "https://issuer.example/status/oversized.jwt"
    md_token = _issue_md(
        private_key, mission_id=mission_id, revocation_ref=status_url + "#idx=0"
    )
    md = mission_module.load_mission_declaration(md_token, public_key)
    dg_token = _issue_dg(
        private_key,
        mission_ref={
            "uri": md_url,
            "mission_id": mission_id,
            "mission_digest": md.payload_digest,
        },
    )

    oversized_body = b"x" * ((2 << 20) + 1)
    _install_fetch_map(
        monkeypatch,
        {
            md_url: md_token,
            status_url: oversized_body,
        },
    )

    session = proxy.start_session(dg_token)
    decision, reason = proxy.evaluate_tool_call(
        session, "read_file", {"path": "/allowed/report.txt"}
    )

    assert decision == Decision.INSUFFICIENT_EVIDENCE
    assert reason == "status_list_too_large"
    with pytest.raises(
        mission_module.MissionStatusUnavailableError, match="size limit"
    ):
        mission_module._fetch_text(status_url)


def test_zip_bomb_rejected(proxy, private_key, public_key, monkeypatch):
    mission_id = "urn:ardur:mission:test:zip-bomb"
    md_url = "https://issuer.example/md/zip-bomb.jwt"
    status_url = "https://issuer.example/status/zip-bomb.jwt"
    revocation_ref = status_url + "#idx=0"
    md_token = _issue_md(
        private_key, mission_id=mission_id, revocation_ref=revocation_ref
    )
    md = mission_module.load_mission_declaration(md_token, public_key)
    dg_token = _issue_dg(
        private_key,
        mission_ref={
            "uri": md_url,
            "mission_id": mission_id,
            "mission_digest": md.payload_digest,
        },
    )

    compressed = zlib.compress(b"\x00" * (mission_module.MAX_DECOMPRESSED_BYTES + 1024))
    claims = jwt.encode(
        {
            "iss": "status-authority",
            "sub": "status-list",
            "iat": int(time.time()),
            "exp": int(time.time()) + 300,
            "status_list": {
                "bits": 1,
                "lst": _b64url(compressed),
            },
        },
        private_key,
        algorithm="ES256",
    )
    _install_fetch_map(
        monkeypatch,
        {
            md_url: md_token,
            status_url: claims,
        },
    )

    session = proxy.start_session(dg_token)
    decision, reason = proxy.evaluate_tool_call(
        session, "read_file", {"path": "/allowed/report.txt"}
    )

    assert decision == Decision.INSUFFICIENT_EVIDENCE
    assert reason == "status_list_too_large"
    with pytest.raises(
        mission_module.MissionStatusUnavailableError, match="decompression limit"
    ):
        mission_module.mission_is_revoked(md, public_key)


def test_mission_cache_avoids_refetching_md(
    proxy, private_key, public_key, monkeypatch
):
    mission_id = "urn:ardur:mission:test:cache"
    md_url = "https://issuer.example/md/cache.jwt"
    status_url = "https://issuer.example/status/cache.jwt"
    md_token = _issue_md(
        private_key, mission_id=mission_id, revocation_ref=status_url + "#idx=3"
    )
    md = mission_module.load_mission_declaration(md_token, public_key)
    dg_token = _issue_dg(
        private_key,
        mission_ref={
            "uri": md_url,
            "mission_id": mission_id,
            "mission_digest": md.payload_digest,
        },
    )
    calls = _install_fetch_map(
        monkeypatch,
        {
            md_url: md_token,
            status_url: _status_list_token(private_key, idx=3, revoked=False),
        },
    )

    session = proxy.start_session(dg_token)
    first = proxy.evaluate_tool_call(session, "read_file", {"path": "/allowed/one.txt"})
    second = proxy.evaluate_tool_call(
        session, "read_file", {"path": "/allowed/two.txt"}
    )

    assert first[0] == Decision.PERMIT
    assert second[0] == Decision.PERMIT
    assert calls.count(md_url) == 1
    assert calls.count(status_url) == 2


@pytest.mark.parametrize(
    "url,reason",
    [
        ("https://169.254.169.254/latest/meta-data/iam/", "AWS IMDS"),
        ("https://127.0.0.1:8080/md.jwt", "loopback"),
        ("https://10.0.0.1/md.jwt", "RFC1918 class A"),
        ("https://192.168.1.10/md.jwt", "RFC1918 class C"),
        ("https://172.16.0.5/md.jwt", "RFC1918 class B"),
        ("https://[::1]/md.jwt", "IPv6 loopback"),
        ("https://[fe80::1]/md.jwt", "IPv6 link-local"),
    ],
)
def test_fetch_rejects_ssrf_target_ip_classes(url, reason):
    """M1 regression: _assert_public_target must reject IP-literal URLs
    pointing at loopback, RFC1918, link-local, and IMDS ranges."""
    with pytest.raises(mission_module.MissionBindingError, match="non-public IP"):
        mission_module._assert_public_target(url)


def test_fetch_accepts_public_ip_literal():
    """M1 sanity: a public IP literal must NOT be blocked by _assert_public_target."""
    mission_module._assert_public_target("https://8.8.8.8/foo")  # should not raise


# --- FIX-3 from S2 hostile audit (2026-04-28): MD loader fail-closed
# -------------------------------------------------------------------
# Before this change, the loader silently treated missing required v0.1
# members as "use safe defaults" — exactly the silent-permit pattern the
# project guards against. These tests lock in that the always-on guard
# now rejects MDs missing any of the six audit-flagged spec members.


class TestMissionDeclarationSchemaGuard:
    @pytest.mark.parametrize(
        "missing_field",
        # probing_rate_limit was removed from the always-required list in
        # the round-3 audit (2026-04-28) because the runtime never
        # consumes the value; it remains required under strict_schema=True.
        # See _REQUIRED_V01_MEMBERS in vibap/mission.py for the rationale.
        [
            "receipt_policy",
            "conformance_profile",
            "tool_manifest_digest",
            "revocation_ref",
            "governed_memory_stores",
        ],
    )
    def test_load_fails_closed_on_missing_required_member(
        self, private_key, public_key, missing_field
    ):
        from conftest import v01_required_md_extras

        mission = MissionPassport(
            agent_id="md-authority",
            mission_id="urn:test:guard",
            mission="schema guard test",
            allowed_tools=["read"],
            forbidden_tools=[],
            resource_scope=[],
            max_tool_calls=2,
            max_duration_s=60,
            delegation_allowed=False,
            max_delegation_depth=0,
        )
        extras = v01_required_md_extras(mission_id="urn:test:guard")
        # Drop the field this parametrization is asserting must be required.
        extras.pop(missing_field, None)
        md_token = issue_passport(mission, private_key, ttl_s=60, extra_claims=extras)

        with pytest.raises(
            mission_module.MissionBindingError,
            match=f"missing required v0.1 member: {missing_field}",
        ):
            mission_module.load_mission_declaration(md_token, public_key)

    def test_load_fails_closed_on_invalid_conformance_profile(
        self, private_key, public_key
    ):
        from conftest import v01_required_md_extras

        mission = MissionPassport(
            agent_id="md-authority",
            mission_id="urn:test:bad-profile",
            mission="bad profile test",
            allowed_tools=["read"],
            forbidden_tools=[],
            resource_scope=[],
            max_tool_calls=2,
            max_duration_s=60,
            delegation_allowed=False,
            max_delegation_depth=0,
        )
        extras = v01_required_md_extras(
            mission_id="urn:test:bad-profile",
            conformance_profile="NotARealProfile",
        )
        md_token = issue_passport(mission, private_key, ttl_s=60, extra_claims=extras)

        with pytest.raises(
            mission_module.MissionBindingError,
            match="conformance_profile",
        ):
            mission_module.load_mission_declaration(md_token, public_key)

    def test_load_fails_closed_on_invalid_tool_manifest_digest(
        self, private_key, public_key
    ):
        from conftest import v01_required_md_extras

        mission = MissionPassport(
            agent_id="md-authority",
            mission_id="urn:test:bad-digest",
            mission="bad digest test",
            allowed_tools=["read"],
            forbidden_tools=[],
            resource_scope=[],
            max_tool_calls=2,
            max_duration_s=60,
            delegation_allowed=False,
            max_delegation_depth=0,
        )
        extras = v01_required_md_extras(mission_id="urn:test:bad-digest")
        extras["tool_manifest_digest"] = "sha-256:not-hex"  # wrong shape
        md_token = issue_passport(mission, private_key, ttl_s=60, extra_claims=extras)

        with pytest.raises(
            mission_module.MissionBindingError,
            match="tool_manifest_digest",
        ):
            mission_module.load_mission_declaration(md_token, public_key)

    def test_load_fails_closed_on_mic_evidence_with_minimal_receipts(
        self, private_key, public_key
    ):
        """Profile/receipt-level interaction: MIC-Evidence forbids minimal receipts."""
        from conftest import v01_required_md_extras

        mission = MissionPassport(
            agent_id="md-authority",
            mission_id="urn:test:mic-vs-minimal",
            mission="mic-evidence test",
            allowed_tools=["read"],
            forbidden_tools=[],
            resource_scope=[],
            max_tool_calls=2,
            max_duration_s=60,
            delegation_allowed=False,
            max_delegation_depth=0,
        )
        extras = v01_required_md_extras(
            mission_id="urn:test:mic-vs-minimal",
            conformance_profile="MIC-Evidence",
            receipt_level="minimal",
        )
        md_token = issue_passport(mission, private_key, ttl_s=60, extra_claims=extras)

        with pytest.raises(
            mission_module.MissionBindingError,
            match="MIC-Evidence",
        ):
            mission_module.load_mission_declaration(md_token, public_key)

    def test_strict_schema_rejects_legacy_field_mixing(self, private_key, public_key):
        """Opt-in strict_schema=True applies the full v0.1 schema, which has
        ``additionalProperties: false`` at the root. Existing MDs from
        :func:`issue_passport` carry legacy fields like ``allowed_tools``
        — they must be rejected when the caller opts into strict mode."""
        from conftest import v01_required_md_extras

        mission = MissionPassport(
            agent_id="md-authority",
            mission_id="urn:test:strict",
            mission="strict schema test",
            allowed_tools=["read"],
            forbidden_tools=[],
            resource_scope=[],
            max_tool_calls=2,
            max_duration_s=60,
            delegation_allowed=False,
            max_delegation_depth=0,
        )
        extras = v01_required_md_extras(mission_id="urn:test:strict")
        md_token = issue_passport(mission, private_key, ttl_s=60, extra_claims=extras)

        with pytest.raises(
            mission_module.MissionBindingError,
            match="violates v0.1 schema",
        ) as excinfo:
            mission_module.load_mission_declaration(
                md_token, public_key, strict_schema=True
            )
        assert excinfo.value.reason == "schema_invalid"


# --- FIX-7 from S2 hostile audit (2026-04-28): SSRF DNS TOCTOU defense
# ---------------------------------------------------------------------
# Before this change, _assert_public_target validated the hostname's
# resolved IPs were public, then urlopen re-resolved at connect time —
# leaving a TOCTOU window where DNS could rebind to 169.254.169.254
# between the check and the connection. The fix is _pinned_urlopen +
# _PinnedIPHTTPSConnection: resolve once, validate once, connect to the
# exact IP that passed validation.


class TestPinnedIPSSRFDefense:
    def test_resolve_to_pinned_public_ip_rejects_all_private_dns(self, monkeypatch):
        """If every IP a hostname resolves to is private, the pinned-IP
        helper must raise — never silently return a private IP for the
        connection to walk into."""

        def fake_getaddrinfo(host, port, *args, **kwargs):
            # All-private resolution (IMDS + RFC1918)
            return [
                (None, None, None, None, ("169.254.169.254", port)),
                (None, None, None, None, ("10.0.0.1", port)),
            ]

        monkeypatch.setattr(mission_module.socket, "getaddrinfo", fake_getaddrinfo)
        with pytest.raises(
            mission_module.MissionBindingError,
            match="all resolved IPs",
        ):
            mission_module._resolve_to_pinned_public_ip("evil.example", 443)

    def test_resolve_to_pinned_public_ip_picks_first_public_ip(self, monkeypatch):
        """Mixed resolution → return the first public IP, skipping any
        leading private entries that would have been rejected."""

        def fake_getaddrinfo(host, port, *args, **kwargs):
            return [
                (None, None, None, None, ("10.0.0.1", port)),  # private, skip
                (None, None, None, None, ("8.8.8.8", port)),  # public, take
                (None, None, None, None, ("169.254.169.254", port)),
            ]

        monkeypatch.setattr(mission_module.socket, "getaddrinfo", fake_getaddrinfo)
        ip = mission_module._resolve_to_pinned_public_ip("mixed.example", 443)
        assert ip == "8.8.8.8"

    def test_pinned_urlopen_uses_resolved_ip_not_dns_at_connect(self, monkeypatch):
        """Production path: _pinned_urlopen resolves once, validates,
        then constructs a _PinnedIPHTTPSConnection with that IP. Any
        re-resolution happening at connect time would defeat FIX-7's
        TOCTOU defense, so this test asserts the connection class
        ignores the hostname for the actual TCP layer.

        We mock create_connection to capture what address the
        connection would have used, and confirm it's the pinned IP.
        """
        # Force resolution to a known public IP
        monkeypatch.setattr(
            mission_module,
            "_resolve_to_pinned_public_ip",
            lambda host, port: "203.0.113.7",  # TEST-NET-3, RFC 5737
        )

        captured = {}

        def fake_create_connection(addr, timeout=None):
            captured["addr"] = addr
            captured["timeout"] = timeout
            raise OSError("intercepted-for-test")

        monkeypatch.setattr(
            mission_module.socket, "create_connection", fake_create_connection
        )

        with pytest.raises(mission_module.URLError):
            mission_module._pinned_urlopen("https://attacker.example/path", timeout=5.0)
        # Confirm the TCP layer used the pinned IP, not the hostname.
        assert captured["addr"] == ("203.0.113.7", 443)


class TestPinnedURLOpenResponseSemantics:
    """Round-4 (FIX-R4-8): the round-3 prompt added redirect-rejection +
    HTTPError-on-non-2xx hardening to ``_pinned_urlopen``, but no
    regression test pinned the new behavior. A refactor that removed
    those branches (or misordered the comparisons) would not be caught.
    These tests close that gap by mocking the underlying HTTPS
    connection at the response level."""

    @staticmethod
    def _stub_pinned_connection(monkeypatch, *, status, headers=None, body=b""):
        """Replace _PinnedIPHTTPSConnection with a stub that returns a
        deterministic response. Avoids real network or pinned-IP DNS."""

        class _StubResponse:
            def __init__(self):
                self.status = status
                self._body = body
                self._closed = False

            def read(self, size: int = -1) -> bytes:
                return self._body if size < 0 else self._body[:size]

            def getheader(self, name, default=None):
                return (headers or {}).get(name, default)

            def getheaders(self):
                return list((headers or {}).items())

            def close(self):
                self._closed = True

        class _StubConn:
            def __init__(self, *a, **kw):
                self.requested = None

            def request(self, method, path, headers=None):
                self.requested = (method, path, headers)

            def getresponse(self):
                return _StubResponse()

            def close(self):
                pass

        monkeypatch.setattr(mission_module, "_PinnedIPHTTPSConnection", _StubConn)
        # And short-circuit IP resolution so the test does not touch DNS.
        monkeypatch.setattr(
            mission_module,
            "_resolve_to_pinned_public_ip",
            lambda host, port: "203.0.113.99",
        )

    def test_redirect_3xx_rejected_with_clear_message(self, monkeypatch):
        self._stub_pinned_connection(
            monkeypatch,
            status=302,
            headers={"Location": "https://elsewhere.example/new"},
        )
        with pytest.raises(mission_module.URLError, match="refused redirect"):
            mission_module._pinned_urlopen("https://example.test/md.jwt", timeout=5.0)

    def test_status_4xx_raises_httperror(self, monkeypatch):
        self._stub_pinned_connection(monkeypatch, status=404, body=b"not found")
        with pytest.raises(urllib.error.HTTPError, match="HTTP 404"):
            mission_module._pinned_urlopen("https://example.test/md.jwt", timeout=5.0)

    def test_status_5xx_raises_httperror(self, monkeypatch):
        self._stub_pinned_connection(monkeypatch, status=503, body=b"upstream sad")
        with pytest.raises(urllib.error.HTTPError, match="HTTP 503"):
            mission_module._pinned_urlopen("https://example.test/md.jwt", timeout=5.0)

    def test_status_200_passes_through(self, monkeypatch):
        body = b"hello"
        self._stub_pinned_connection(monkeypatch, status=200, body=body)
        resp = mission_module._pinned_urlopen(
            "https://example.test/md.jwt", timeout=5.0
        )
        with resp as response:
            assert response.read() == body


# --- Round-3 audit (2026-04-28) follow-on: bounded iat gate generalized
# from receipts to MD/status-list/AAT/passport. Round-2 audit flagged
# that FIX-6 only protected receipts; an attacker who briefly captured a
# signer could mint MDs/passports/AATs with iat=year_3000 + exp=year_3001
# that the verifier accepted forever. These tests pin the
# generalization so the gap doesn't reopen silently.


class _ShimResponse:
    """Minimal urlopen-like response shim for status-list mock tests."""

    def __init__(self, body: bytes | str) -> None:
        self._body = body.encode() if isinstance(body, str) else body

    def read(self, size: int = -1) -> bytes:
        return self._body if size < 0 else self._body[:size]

    def __enter__(self) -> "_ShimResponse":
        return self

    def __exit__(self, *exc) -> bool:
        return False


class TestStatusListIatSkewGuard:
    """Status-list JWTs flow through ``mission_is_revoked``. The round-3
    audit pointed out the test class header above advertised this case
    but never wrote it. Round-4 closes that gap (FIX-R4-7)."""

    def test_status_list_with_iat_in_far_future_fails_closed(
        self, private_key, public_key, monkeypatch
    ):
        mission = MissionPassport(
            agent_id="md-authority",
            mission_id="urn:test:status-list-iat",
            mission="status-list iat-skew test",
            allowed_tools=["read"],
            forbidden_tools=[],
            resource_scope=[],
            max_tool_calls=2,
            max_duration_s=60,
            delegation_allowed=False,
            max_delegation_depth=0,
        )
        status_url = "https://issuer.example/status/skew-test.jwt"
        md_token = issue_passport(
            mission,
            private_key,
            ttl_s=60,
            extra_claims=v01_required_md_extras(
                mission_id="urn:test:status-list-iat",
                revocation_ref=f"{status_url}#idx=0",
            ),
        )
        md = mission_module.load_mission_declaration(md_token, public_key)

        # Mint a status list whose iat is far in the future.
        far_future = int(time.time()) + 365 * 86400
        future_status_claims = {
            "iss": "status-authority",
            "sub": "status-list",
            "iat": far_future,
            "exp": far_future + 300,
            "status_list": {
                "bits": 1,
                "lst": _b64url(zlib.compress(b"\x00")),
            },
        }
        future_status_token = jwt.encode(
            future_status_claims, private_key, algorithm="ES256"
        )

        monkeypatch.setattr(
            mission_module,
            "urlopen",
            lambda req, **kw: _ShimResponse(future_status_token),
        )
        with pytest.raises(
            mission_module.MissionBindingError,
            match="status list iat lies more than",
        ):
            mission_module.mission_is_revoked(md, public_key)


class TestMissionDeclarationIatSkewGuard:
    def test_md_with_iat_in_far_future_fails_closed(self, private_key, public_key):
        from conftest import v01_required_md_extras

        mission = MissionPassport(
            agent_id="md-authority",
            mission="far-future iat",
            allowed_tools=["read"],
            forbidden_tools=[],
            resource_scope=[],
            max_tool_calls=2,
            max_duration_s=60,
            delegation_allowed=False,
            max_delegation_depth=0,
        )
        far_future = int(time.time()) + 365 * 86400
        # issue_passport sets iat=now; mint manually to inject far-future iat.
        claims: dict[str, object] = {
            "iss": "md-authority",
            "sub": "md-authority",
            "aud": "vibap-proxy",
            "iat": far_future,
            "exp": far_future + 600,
            "jti": "md-far-future",
            "mission_id": "urn:test:far-future",
            **v01_required_md_extras(mission_id="urn:test:far-future"),
            "allowed_tools": list(mission.allowed_tools),
            "forbidden_tools": list(mission.forbidden_tools),
            "resource_scope": list(mission.resource_scope),
            "max_tool_calls": mission.max_tool_calls,
            "max_duration_s": mission.max_duration_s,
            "delegation_allowed": mission.delegation_allowed,
            "max_delegation_depth": mission.max_delegation_depth,
        }
        token = jwt.encode(claims, private_key, algorithm="ES256")
        with pytest.raises(
            mission_module.MissionBindingError,
            match="MD iat lies more than",
        ):
            mission_module.load_mission_declaration(token, public_key)
