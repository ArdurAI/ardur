from __future__ import annotations

import inspect
import json
from pathlib import Path

import pytest
from biscuit_auth import KeyPair
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

import spiffe_doubles
from vibap import cli
from vibap import spiffe_identity
from vibap.passport import generate_keypair
from vibap.personal_hub import PersonalHub
from vibap.proxy import GovernanceProxy


SHIPPED_SPIFFE_ENDPOINT_SOCKET = "unix:///run/spire/sockets/agent.sock"
COMPOSE_FILE = Path(__file__).resolve().parents[2] / "docker-compose.yml"
HUB_DOCKERFILE = Path(__file__).resolve().parents[2] / "Dockerfile.hub"
SPIRE_SETUP = (
    Path(__file__).resolve().parents[2] / "deploy" / "local" / "spire" / "setup.sh"
)


def _write_biscuit_public_key(path, keypair: KeyPair) -> None:
    path.write_bytes(
        ed25519.Ed25519PublicKey.from_public_bytes(
            bytes(keypair.public_key.to_bytes())
        ).public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def test_fetch_svid_default_matches_shipped_workload_api_socket() -> None:
    default = inspect.signature(spiffe_identity.fetch_svid).parameters[
        "socket_path"
    ].default

    assert default == SHIPPED_SPIFFE_ENDPOINT_SOCKET


def test_compose_exposes_supported_spiffe_configuration() -> None:
    compose = COMPOSE_FILE.read_text(encoding="utf-8")

    assert compose.count(
        "SPIFFE_ENDPOINT_SOCKET=${SPIFFE_ENDPOINT_SOCKET:-"
        f"{SHIPPED_SPIFFE_ENDPOINT_SOCKET}" + "}"
    ) == 2
    for variable in (
        "ARDUR_BISCUIT_PEER_TRUST_BUNDLE",
        "ARDUR_BISCUIT_PEER_TRUST_DOMAIN",
        "ARDUR_BISCUIT_ISSUER_PUBLIC_KEY",
        "ARDUR_BISCUIT_SVID_AUDIENCE",
    ):
        assert f"{variable}=${{{variable}:-" in compose


def test_compose_preserves_unix_attestation_and_distinct_workload_ids() -> None:
    compose = COMPOSE_FILE.read_text(encoding="utf-8")
    hub_dockerfile = HUB_DOCKERFILE.read_text(encoding="utf-8")
    spire_setup = SPIRE_SETUP.read_text(encoding="utf-8")

    assert compose.count('pid: "service:spire-agent"') == 2
    assert compose.count('      - "1000"') == 2
    assert "groupadd -r ardur --gid 65533" in hub_dockerfile
    assert "useradd -r -g ardur --uid 65533 ardur" in hub_dockerfile
    hub_entry = spire_setup.split("# Personal hub", maxsplit=1)[1].split(
        "# Test runner", maxsplit=1
    )[0]
    assert "-selector unix:uid:65533" in hub_entry


def test_start_and_hub_read_spiffe_socket_from_environment(monkeypatch) -> None:
    monkeypatch.setenv("SPIFFE_ENDPOINT_SOCKET", SHIPPED_SPIFFE_ENDPOINT_SOCKET)

    parser = cli.build_parser()

    assert (
        parser.parse_args(["start"]).spiffe_endpoint_socket
        == SHIPPED_SPIFFE_ENDPOINT_SOCKET
    )
    assert (
        parser.parse_args(["hub"]).spiffe_endpoint_socket
        == SHIPPED_SPIFFE_ENDPOINT_SOCKET
    )


def test_start_reads_peer_verification_configuration_from_environment(
    monkeypatch,
) -> None:
    monkeypatch.setenv("ARDUR_BISCUIT_PEER_TRUST_BUNDLE", "/config/bundle.json")
    monkeypatch.setenv("ARDUR_BISCUIT_PEER_TRUST_DOMAIN", "ardur.dev")
    monkeypatch.setenv("ARDUR_BISCUIT_ISSUER_PUBLIC_KEY", "/config/issuer.pem")
    monkeypatch.setenv("ARDUR_BISCUIT_SVID_AUDIENCE", "configured-audience")

    args = cli.build_parser().parse_args(["start"])

    assert args.biscuit_peer_trust_bundle == "/config/bundle.json"
    assert args.biscuit_peer_trust_domain == "ardur.dev"
    assert args.biscuit_issuer_public_key == "/config/issuer.pem"
    assert args.biscuit_svid_audience == "configured-audience"


@pytest.mark.parametrize("bundle_shape", ["workload-api", "federation"])
def test_raw_spire_bundle_shapes_load_for_proxy_verification(
    tmp_path, bundle_shape
) -> None:
    source = spiffe_doubles.make_mock_trust_bundle()
    jwt_key = next(
        dict(key) for key in source.jwks["keys"] if key.get("use") == "jwt-svid"
    )
    if bundle_shape == "workload-api":
        jwt_key.pop("use")
        raw_bundle = {"keys": [jwt_key]}
    else:
        x509_key = dict(jwt_key)
        x509_key["use"] = "x509-svid"
        raw_bundle = {"keys": [x509_key, jwt_key], "spiffe_sequence": 1}
    bundle_path = tmp_path / f"{bundle_shape}.json"
    bundle_path.write_text(json.dumps(raw_bundle), encoding="utf-8")

    loaded = spiffe_identity.load_trust_bundle(
        str(bundle_path), trust_domain="example.org"
    )
    private_key, public_key = generate_keypair(keys_dir=tmp_path / "keys")

    proxy = GovernanceProxy(
        log_path=tmp_path / "governance.jsonl",
        state_dir=tmp_path / "state",
        keys_dir=tmp_path / "keys",
        private_key=private_key,
        public_key=public_key,
        biscuit_issuer_public_key=KeyPair().public_key,
        biscuit_peer_trust_bundle=loaded,
        biscuit_svid_audience="ardur-proxy",
    )

    assert proxy._biscuit_peer_trust_bundle.trust_domain == "example.org"


def test_start_wires_configured_peer_verification_into_proxy(
    tmp_path, monkeypatch
) -> None:
    source = spiffe_doubles.make_mock_trust_bundle()
    jwt_key = next(
        dict(key) for key in source.jwks["keys"] if key.get("use") == "jwt-svid"
    )
    jwt_key.pop("use")
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(json.dumps({"keys": [jwt_key]}), encoding="utf-8")

    issuer_keypair = KeyPair()
    issuer_key_path = tmp_path / "issuer.pem"
    _write_biscuit_public_key(issuer_key_path, issuer_keypair)
    captured: dict[str, object] = {}

    class FakeGovernanceProxy:
        def __init__(self, **kwargs):
            captured["proxy_kwargs"] = kwargs

    monkeypatch.setattr(cli, "generate_keypair", lambda **_kwargs: (object(), object()))
    monkeypatch.setattr(cli, "GovernanceProxy", FakeGovernanceProxy)
    monkeypatch.setattr(cli, "serve_proxy", lambda **_kwargs: None)

    args = cli.build_parser().parse_args(
        [
            "start",
            "--biscuit-peer-trust-bundle",
            str(bundle_path),
            "--biscuit-peer-trust-domain",
            "example.org",
            "--biscuit-issuer-public-key",
            str(issuer_key_path),
            "--biscuit-svid-audience",
            "peer-audience",
            "--no-tls",
        ]
    )

    assert cli.cmd_start(args) == 0
    proxy_kwargs = captured["proxy_kwargs"]
    assert proxy_kwargs["biscuit_peer_trust_bundle"].jwks == {"keys": [jwt_key]}
    assert bytes(proxy_kwargs["biscuit_issuer_public_key"].to_bytes()) == bytes(
        issuer_keypair.public_key.to_bytes()
    )
    assert proxy_kwargs["biscuit_svid_audience"] == "peer-audience"


def test_start_keeps_peer_verification_off_by_default(monkeypatch) -> None:
    for name in (
        "ARDUR_BISCUIT_PEER_TRUST_BUNDLE",
        "ARDUR_BISCUIT_PEER_TRUST_DOMAIN",
        "ARDUR_BISCUIT_ISSUER_PUBLIC_KEY",
        "ARDUR_BISCUIT_SVID_AUDIENCE",
        "SPIFFE_ENDPOINT_SOCKET",
    ):
        monkeypatch.delenv(name, raising=False)
    captured: dict[str, object] = {}

    class FakeGovernanceProxy:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    monkeypatch.setattr(cli, "generate_keypair", lambda **_kwargs: (object(), object()))
    monkeypatch.setattr(cli, "GovernanceProxy", FakeGovernanceProxy)
    monkeypatch.setattr(cli, "serve_proxy", lambda **_kwargs: None)

    assert cli.cmd_start(cli.build_parser().parse_args(["start", "--no-tls"])) == 0
    assert captured["biscuit_peer_trust_bundle"] is None
    assert captured["biscuit_issuer_public_key"] is None


def test_start_rejects_partial_peer_verification_configuration(
    tmp_path, monkeypatch, capsys
) -> None:
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text('{"keys": []}', encoding="utf-8")

    def forbidden_startup(*_args, **_kwargs):  # pragma: no cover - assertion path
        raise AssertionError("startup must stop after invalid peer configuration")

    monkeypatch.setattr(cli, "generate_keypair", forbidden_startup)
    monkeypatch.setattr(cli, "serve_proxy", forbidden_startup)
    args = cli.build_parser().parse_args(
        ["start", "--biscuit-peer-trust-bundle", str(bundle_path), "--no-tls"]
    )

    assert cli.cmd_start(args) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["error"] == "biscuit_peer_verification_config_invalid"


def test_start_rejects_x509_only_peer_trust_bundle(
    tmp_path, monkeypatch, capsys
) -> None:
    source = spiffe_doubles.make_mock_trust_bundle()
    x509_key = next(
        dict(key) for key in source.jwks["keys"] if key.get("use") == "jwt-svid"
    )
    x509_key["use"] = "x509-svid"
    bundle_path = tmp_path / "x509-only.json"
    bundle_path.write_text(json.dumps({"keys": [x509_key]}), encoding="utf-8")
    issuer_key_path = tmp_path / "issuer.pem"
    _write_biscuit_public_key(issuer_key_path, KeyPair())

    def forbidden_startup(*_args, **_kwargs):  # pragma: no cover - assertion path
        raise AssertionError("startup must stop after x509-only peer bundle")

    monkeypatch.setattr(cli, "generate_keypair", forbidden_startup)
    monkeypatch.setattr(cli, "serve_proxy", forbidden_startup)
    args = cli.build_parser().parse_args(
        [
            "start",
            "--biscuit-peer-trust-bundle",
            str(bundle_path),
            "--biscuit-peer-trust-domain",
            "example.org",
            "--biscuit-issuer-public-key",
            str(issuer_key_path),
            "--no-tls",
        ]
    )

    assert cli.cmd_start(args) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["error"] == "biscuit_peer_verification_config_invalid"


def test_start_fetches_and_retains_configured_workload_identity(monkeypatch) -> None:
    captured: dict[str, object] = {}
    workload_identity = spiffe_doubles.make_mock_svid_bundle()

    def fake_fetch_svid(socket_path: str):
        captured["socket_path"] = socket_path
        return workload_identity

    class FakeGovernanceProxy:
        def __init__(self, **kwargs):
            captured["proxy_kwargs"] = kwargs

    def fake_serve_proxy(**kwargs):
        captured["serve_proxy_kwargs"] = kwargs

    monkeypatch.setattr(cli, "fetch_svid", fake_fetch_svid, raising=False)
    monkeypatch.setattr(cli, "generate_keypair", lambda **_kwargs: (object(), object()))
    monkeypatch.setattr(cli, "GovernanceProxy", FakeGovernanceProxy)
    monkeypatch.setattr(cli, "serve_proxy", fake_serve_proxy)

    args = cli.build_parser().parse_args(
        [
            "start",
            "--spiffe-endpoint-socket",
            SHIPPED_SPIFFE_ENDPOINT_SOCKET,
            "--no-tls",
        ]
    )

    assert cli.cmd_start(args) == 0
    assert captured["socket_path"] == SHIPPED_SPIFFE_ENDPOINT_SOCKET
    assert captured["proxy_kwargs"]["workload_identity"] is workload_identity


def test_start_rejects_unreachable_configured_spiffe_socket(
    monkeypatch, capsys
) -> None:
    def fail_fetch_svid(_socket_path: str):
        raise OSError("socket unavailable")

    def forbidden_startup(*_args, **_kwargs):  # pragma: no cover - assertion path
        raise AssertionError("startup must stop after SPIFFE fetch failure")

    monkeypatch.setattr(cli, "fetch_svid", fail_fetch_svid)
    monkeypatch.setattr(cli, "generate_keypair", forbidden_startup)
    monkeypatch.setattr(cli, "serve_proxy", forbidden_startup)

    args = cli.build_parser().parse_args(
        [
            "start",
            "--spiffe-endpoint-socket",
            "unix:///missing/agent.sock",
            "--no-tls",
        ]
    )

    assert cli.cmd_start(args) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["error"] == "spiffe_svid_fetch_failed"
    assert "SPIFFE_ENDPOINT_SOCKET" in payload["detail"]


def test_hub_fetches_and_forwards_configured_workload_identity(monkeypatch) -> None:
    captured: dict[str, object] = {}
    workload_identity = spiffe_doubles.make_mock_svid_bundle()

    def fake_fetch_svid(socket_path: str):
        captured["socket_path"] = socket_path
        return workload_identity

    def fake_serve_hub(**kwargs):
        captured["serve_hub_kwargs"] = kwargs

    monkeypatch.setattr(cli, "fetch_svid", fake_fetch_svid)
    monkeypatch.setattr(cli, "serve_hub", fake_serve_hub)

    args = cli.build_parser().parse_args(
        [
            "hub",
            "--spiffe-endpoint-socket",
            SHIPPED_SPIFFE_ENDPOINT_SOCKET,
            "--no-tls",
        ]
    )

    assert cli.cmd_hub(args) == 0
    assert captured["socket_path"] == SHIPPED_SPIFFE_ENDPOINT_SOCKET
    assert (
        captured["serve_hub_kwargs"]["workload_identity"] is workload_identity
    )


def test_personal_hub_retains_workload_identity_in_its_proxy(tmp_path) -> None:
    workload_identity = spiffe_doubles.make_mock_svid_bundle()

    hub = PersonalHub(tmp_path, workload_identity=workload_identity)

    assert hub.proxy._workload_identity is workload_identity


def test_proxy_keeps_workload_identity_private_key_in_memory_only(tmp_path) -> None:
    keys_dir = tmp_path / "keys"
    private_key, public_key = generate_keypair(keys_dir=keys_dir)
    workload_identity = spiffe_doubles.make_mock_svid_bundle()

    proxy = GovernanceProxy(
        log_path=tmp_path / "governance.jsonl",
        state_dir=tmp_path / "state",
        keys_dir=keys_dir,
        private_key=private_key,
        public_key=public_key,
        workload_identity=workload_identity,
    )

    assert proxy._workload_identity is workload_identity
    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert workload_identity.private_key_pem not in path.read_bytes()
