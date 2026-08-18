from __future__ import annotations

from pathlib import Path
import re

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 CI
    import tomli as tomllib


PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"


def _package_names(requirements: list[str]) -> set[str]:
    names: set[str] = set()
    for requirement in requirements:
        match = re.match(r"[A-Za-z0-9_.-]+", requirement)
        assert match is not None
        names.add(re.sub(r"[-_.]+", "-", match.group()).lower())
    return names


def test_spiffe_identity_dependencies_are_installed_without_dev_extras() -> None:
    with PYPROJECT.open("rb") as handle:
        config = tomllib.load(handle)

    runtime = _package_names(config["project"]["dependencies"])
    dev = _package_names(config["project"]["optional-dependencies"]["dev"])

    assert {"spiffe", "biscuit-python", "pyasn1"} <= runtime
    assert {"spiffe", "biscuit-python", "pyasn1"}.isdisjoint(dev)
