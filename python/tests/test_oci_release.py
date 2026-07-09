from __future__ import annotations

import json
import re
import stat
import subprocess
import sys
from pathlib import Path

import yaml

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 CI path
    import tomli as tomllib


REPO_ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = REPO_ROOT / "Dockerfile.proxy"
LOCKFILE = REPO_ROOT / "packaging" / "oci" / "runtime-requirements.lock"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "oci-proxy.yml"
VALIDATOR = REPO_ROOT / "scripts" / "validate-oci-release.py"
SMOKE_SCRIPT = REPO_ROOT / "scripts" / "verify-proxy-image.sh"
REFERENCE = REPO_ROOT / "docs" / "reference" / "proxy-oci-image.md"

ACTION_SHAS = {
    "checkout": "9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
    "setup-python": "ece7cb06caefa5fff74198d8649806c4678c61a1",
    "upload-artifact": "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
    "download-artifact": "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
    "setup-qemu": "96fe6ef7f33517b61c61be40b68a1882f3264fb8",
    "setup-buildx": "bb05f3f5519dd87d3ba754cc423b652a5edd6d2c",
    "login": "af1e73f918a031802d376d3c8bbc3fe56130a9b0",
    "build-push": "53b7df96c91f9c12dcc8a07bcb9ccacbed38856a",
    "trivy": "ed142fd0673e97e23eac54620cfb913e5ce36c25",
}
SBOM_GENERATOR = (
    "docker/buildkit-syft-scanner:stable-1@"
    "sha256:79e7b013cbec16bbb436f312819a49a4a57752b2270c1a9332ae1a10fcc82a68"
)


def _project_version() -> str:
    with (REPO_ROOT / "python" / "pyproject.toml").open("rb") as handle:
        return tomllib.load(handle)["project"]["version"]


def _workflow() -> dict[str, object]:
    with WORKFLOW.open(encoding="utf-8") as handle:
        return yaml.load(handle, Loader=yaml.BaseLoader)


def _run_validator(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(VALIDATOR), *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def test_oci_validator_accepts_contract_and_exact_release_tag() -> None:
    version = _project_version()
    normal = _run_validator()
    exact_tag = _run_validator("--expected-tag", f"v{version}")
    printed = _run_validator("--print-version")

    assert normal.returncode == 0, normal.stdout + normal.stderr
    assert normal.stdout.strip() == f"validated ghcr.io/ardurai/ardur-proxy:{version}"
    assert exact_tag.returncode == 0, exact_tag.stdout + exact_tag.stderr
    assert printed.returncode == 0, printed.stdout + printed.stderr
    assert printed.stdout.strip() == version


def test_oci_validator_rejects_mismatched_release_tag() -> None:
    result = _run_validator("--expected-tag", "v999.0.0")

    assert result.returncode == 1
    assert "release tag must be" in result.stderr


def test_proxy_image_is_digest_pinned_non_root_and_hash_locked() -> None:
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")
    lock = LOCKFILE.read_text(encoding="utf-8")

    assert re.search(
        r"^ARG PYTHON_IMAGE=python:3\.13\.14-slim-trixie@sha256:[0-9a-f]{64}$",
        dockerfile,
        flags=re.MULTILINE,
    )
    assert "--require-hashes" in dockerfile
    assert "python -m pip check" in dockerfile
    assert "USER 65532:65532" in dockerfile
    assert "VIBAP_HOME=/home/ardur/.ardur" in dockerfile
    assert 'VOLUME ["/home/ardur/.ardur"]' in dockerfile
    assert "ARDUR_API_TOKEN=" not in dockerfile
    assert "VIBAP_API_TOKEN=" not in dockerfile
    assert lock.count("--hash=sha256:") >= 18
    assert "--index-url" not in lock
    assert "--trusted-host" not in lock


def test_proxy_smoke_enforces_runtime_restrictions_and_real_lifecycle() -> None:
    smoke = SMOKE_SCRIPT.read_text(encoding="utf-8")

    assert stat.S_IMODE(SMOKE_SCRIPT.stat().st_mode) == 0o755
    for required in (
        "--read-only",
        "--cap-drop ALL",
        "--security-opt no-new-privileges",
        "--tmpfs /home/ardur/.ardur",
        "scripts/verify-mvp.sh",
        "VIBAP_API_TOKEN=$API_TOKEN",
    ):
        assert required in smoke
    assert "docker logs" in smoke
    assert 'grep --fixed-strings "$API_TOKEN"' in smoke


def test_oci_workflow_is_pinned_scanned_attested_and_release_only() -> None:
    workflow = _workflow()
    text = WORKFLOW.read_text(encoding="utf-8")
    serialized = json.dumps(workflow)

    assert set(workflow["on"]) == {
        "pull_request",
        "push",
        "release",
        "workflow_dispatch",
    }
    assert workflow["permissions"] == {"contents": "read"}
    assert workflow["env"] == {
        "IMAGE_NAME": "ghcr.io/ardurai/ardur-proxy",
        "TRIVY_VERSION": "v0.72.0",
    }

    jobs = workflow["jobs"]
    assert set(jobs) == {
        "validate",
        "proxy-smoke",
        "release-platform",
        "publish-manifest",
    }
    release_if = (
        "github.event_name == 'release' && github.event.release.prerelease == false"
    )
    assert jobs["release-platform"]["if"] == release_if
    assert jobs["publish-manifest"]["if"] == release_if
    assert jobs["release-platform"]["needs"] == ["validate", "proxy-smoke"]
    assert jobs["publish-manifest"]["needs"] == "release-platform"
    assert jobs["release-platform"]["environment"]["name"] == "ghcr"
    assert jobs["publish-manifest"]["environment"]["name"] == "ghcr"
    assert jobs["release-platform"]["permissions"] == {
        "contents": "read",
        "id-token": "write",
        "packages": "write",
    }
    assert jobs["publish-manifest"]["permissions"] == {
        "contents": "read",
        "packages": "write",
    }

    platforms = jobs["release-platform"]["strategy"]["matrix"]["include"]
    assert platforms == [
        {"platform": "linux/amd64", "artifact": "linux-amd64"},
        {"platform": "linux/arm64", "artifact": "linux-arm64"},
    ]
    release_steps = [
        step["name"] for step in jobs["release-platform"]["steps"] if "name" in step
    ]
    assert release_steps.index("Gate final platform digest") < release_steps.index(
        "Record scanned digest"
    )
    manifest_steps = [
        step["name"] for step in jobs["publish-manifest"]["steps"] if "name" in step
    ]
    assert manifest_steps[-2:] == [
        "Publish immutable version tags",
        "Verify public manifest and record digest",
    ]

    assert "type=provenance,mode=max" in text
    assert f"type=sbom,generator={SBOM_GENERATOR}" in text
    assert "push-by-digest=true" in text
    assert 'ignore-unfixed: "true"' in text
    assert "scanners: vuln,secret" in text
    assert 'git merge-base --is-ancestor "$GITHUB_SHA" origin/main' in text
    assert "secrets." not in serialized
    assert ":latest" not in text
    assert "skip-existing" not in text

    uses_values = re.findall(r"\buses:\s*([^\s#]+)", text)
    assert uses_values
    assert all(re.fullmatch(r"[^@]+@[0-9a-f]{40}", value) for value in uses_values)
    for sha in ACTION_SHAS.values():
        assert any(value.endswith(f"@{sha}") for value in uses_values)


def test_oci_reference_keeps_public_claim_gated_and_documents_operations() -> None:
    reference = REFERENCE.read_text(encoding="utf-8")

    assert "does not claim that an Ardur image is public" in reference
    assert "ghcr.io/ardurai/ardur-proxy@sha256:<published-digest>" in reference
    for required in (
        "UID/GID `65532:65532`",
        "`/home/ardur/.ardur`",
        "`VIBAP_API_TOKEN`",
        "`ARDUR_NO_TLS=1`",
        "read-only root filesystem",
        "SBOM",
        "provenance",
        "GHCR storage and egress",
    ):
        assert required in reference
