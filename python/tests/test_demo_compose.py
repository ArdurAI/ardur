from __future__ import annotations

from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
COMPOSE_FILE = REPO_ROOT / "docker-compose.yml"
MAKEFILE = REPO_ROOT / "Makefile"
TESTS_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "tests.yml"


def test_spire_volume_initializer_prepares_nonroot_writable_volumes() -> None:
    """Keep fresh named volumes writable for SPIRE's uid-1000 server image."""

    compose = yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))
    services = compose["services"]
    initializer = services["spire-volume-init"]

    assert initializer["image"] == "alpine:3.22"
    assert initializer["user"] == "0:0"
    assert initializer["entrypoint"][:2] == ["/bin/sh", "-ec"]
    assert initializer["volumes"] == [
        "spire-server-data:/run/spire/server-data",
        "spire-shared:/run/spire/shared",
    ]
    assert "chown -R 1000:1000" in initializer["entrypoint"][-1]
    assert services["spire-server"]["depends_on"] == {
        "spire-volume-init": {"condition": "service_completed_successfully"}
    }
    assert "spire-shared:/run/spire/sockets" in services["spire-server"]["volumes"]
    assert services["spire-server"]["healthcheck"]["test"] == [
        "CMD",
        "/opt/spire/bin/spire-server",
        "healthcheck",
        "-socketPath",
        "/run/spire/sockets/server.sock",
    ]
    assert services["spire-init"] == {
        "build": {"context": ".", "dockerfile": "deploy/local/spire/Dockerfile.init"},
        "entrypoint": ["/bin/sh", "/tmp/setup.sh"],
        "volumes": [
            "spire-shared:/tmp/spire-shared",
            "spire-shared:/run/spire/sockets",
            "./deploy/local/spire/setup.sh:/tmp/setup.sh:ro",
        ],
        "depends_on": {"spire-server": {"condition": "service_healthy"}},
    }
    assert "spire-shared:/tmp/spire-shared:ro" in services["spire-agent"]["volumes"]
    assert "spire-shared:/run/spire/sockets" in services["spire-agent"]["volumes"]
    assert "spire-shared:/run/spire/bundle:ro" in services["spire-agent"]["volumes"]
    assert services["spire-agent"]["command"] == [
        "-config",
        "/run/spire/config/agent.conf",
        "-joinTokenFile",
        "/tmp/spire-shared/join_token",
    ]


def test_spire_init_image_keeps_the_pinned_server_binary() -> None:
    dockerfile = (
        REPO_ROOT / "deploy" / "local" / "spire" / "Dockerfile.init"
    ).read_text(encoding="utf-8")

    assert "FROM ghcr.io/spiffe/spire-server:1.14.4 AS spire-server" in dockerfile
    assert "FROM alpine:3.22" in dockerfile
    assert (
        "COPY --from=spire-server /opt/spire/bin/spire-server /opt/spire/bin/spire-server"
        in dockerfile
    )


def test_local_spire_config_does_not_require_a_kubernetes_api() -> None:
    config = (REPO_ROOT / "deploy" / "local" / "spire" / "server.conf").read_text(
        encoding="utf-8"
    )

    assert 'Notifier "k8sbundle"' not in config
    assert 'database_type = "sqlite3"' in config
    assert 'NodeAttestor "join_token"' in config


def test_local_spire_setup_uses_the_shared_server_api_socket() -> None:
    setup = (REPO_ROOT / "deploy" / "local" / "spire" / "setup.sh").read_text(
        encoding="utf-8"
    )

    assert setup.startswith("#!/bin/sh\n")
    assert "-serverAddr" not in setup
    assert setup.count("-socketPath /run/spire/sockets/server.sock") == 6
    assert "spiffe://ardur.dev/spire/agent" not in setup
    assert setup.count("spiffe://ardur.dev/agent/local") == 4
    assert "-ttl 3600" not in setup
    assert setup.count("-x509SVIDTTL 3600") == 3
    assert "-format pem > /tmp/spire-shared/bundle.crt" in setup
    assert "-ttl 600 | sed -n 's/^Token: //p'" in setup
    assert 'test -n "$JOIN_TOKEN"' in setup


def test_demo_host_ports_keep_defaults_and_allow_parallel_overrides() -> None:
    compose = yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))
    services = compose["services"]

    assert services["spire-server"]["ports"] == [
        "${ARDUR_SPIRE_SERVER_PORT:-8081}:8081"
    ]
    assert services["proxy"]["ports"] == ["${ARDUR_PROXY_PORT:-8443}:8443"]
    assert services["hub"]["ports"] == ["${ARDUR_HUB_PORT:-8765}:8765"]


def test_make_demo_supports_ci_wait_without_changing_interactive_default() -> None:
    makefile = MAKEFILE.read_text(encoding="utf-8")

    assert "DEMO_UP_ARGS ?=" in makefile
    assert "docker compose up --build $(DEMO_UP_ARGS)" in makefile


def test_demo_stack_is_a_required_ci_lifecycle_gate() -> None:
    workflow = yaml.safe_load(TESTS_WORKFLOW.read_text(encoding="utf-8"))
    jobs = workflow["jobs"]
    demo = jobs["demo-smoke"]
    steps = {step.get("name"): step for step in demo["steps"] if "name" in step}

    assert demo["runs-on"] == "ubuntu-24.04"
    assert demo["timeout-minutes"] == 15
    assert demo["env"]["ARDUR_API_TOKEN"] == "ci-demo-token"
    assert steps["Start the full demo stack and wait for health"]["run"] == (
        'make demo DEMO_UP_ARGS="--detach --wait --wait-timeout 240"'
    )
    assert steps["Verify health, PERMIT, DENY, and signed attestation"]["run"] == (
        "./scripts/verify-mvp.sh"
    )
    assert steps["Show demo status and logs on failure"]["if"] == "failure()"
    assert "docker compose logs --no-color" in steps[
        "Show demo status and logs on failure"
    ]["run"]
    assert steps["Remove demo containers and volumes"]["if"] == "always()"
    assert steps["Remove demo containers and volumes"]["run"] == "make demo-down"

    aggregate = jobs["tests"]
    assert "demo-smoke" in aggregate["needs"]
    gate = aggregate["steps"][0]
    assert gate["env"]["DEMO_SMOKE"] == "${{ needs['demo-smoke'].result }}"
    assert 'require_success demo-smoke "$DEMO_SMOKE"' in gate["run"]
