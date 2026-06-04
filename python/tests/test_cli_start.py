from __future__ import annotations

from vibap import cli


def test_start_api_token_argument_is_forwarded_to_serve_proxy(monkeypatch):
    captured: dict[str, object] = {}

    class FakeGovernanceProxy:
        def __init__(self, **kwargs):
            captured["proxy_kwargs"] = kwargs

    def fake_generate_keypair(*, keys_dir=None):
        captured["keys_dir"] = keys_dir
        return object(), object()

    def fake_serve_proxy(**kwargs):
        captured["serve_proxy_kwargs"] = kwargs

    monkeypatch.setattr(cli, "GovernanceProxy", FakeGovernanceProxy)
    monkeypatch.setattr(cli, "generate_keypair", fake_generate_keypair)
    monkeypatch.setattr(cli, "serve_proxy", fake_serve_proxy)

    parser = cli.build_parser()
    args = parser.parse_args(
        [
            "start",
            "--host",
            "127.0.0.1",
            "--port",
            "9876",
            "--api-token",
            "configured-token-for-test",
            "--no-tls",
        ]
    )

    assert args.api_token == "configured-token-for-test"
    assert cli.cmd_start(args) == 0

    serve_kwargs = captured["serve_proxy_kwargs"]
    assert isinstance(serve_kwargs, dict)
    assert serve_kwargs["api_token"] == "configured-token-for-test"
    assert serve_kwargs["require_auth"] is True
    assert serve_kwargs["no_tls"] is True
    assert serve_kwargs["host"] == "127.0.0.1"
    assert serve_kwargs["port"] == 9876
