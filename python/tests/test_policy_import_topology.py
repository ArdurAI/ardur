"""Regression tests for the policy/backend import topology."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest


PYTHON_ROOT = Path(__file__).resolve().parents[1]
VIBAP_ROOT = PYTHON_ROOT / "vibap"
TARGET_MODULES = {
    "vibap.proxy": VIBAP_ROOT / "proxy.py",
    "vibap.policy_backend": VIBAP_ROOT / "policy_backend.py",
    "vibap.native_checks": VIBAP_ROOT / "native_checks.py",
    "vibap.backends": VIBAP_ROOT / "backends" / "__init__.py",
    "vibap.backends.native": VIBAP_ROOT / "backends" / "native.py",
    "vibap.backends.forbid_rules": VIBAP_ROOT / "backends" / "forbid_rules.py",
    "vibap.backends.cedar": VIBAP_ROOT / "backends" / "cedar.py",
}


def _resolve_import_from(module_name: str, node: ast.ImportFrom) -> set[str]:
    """Return module names imported by an ImportFrom node.

    ``ast`` stores ``from . import proxy`` as ``module=None`` and alias
    ``proxy``; for topology checks we need to resolve that to ``vibap.proxy``.
    For ``from .policy_backend import PolicyDecision`` the dependency is the
    module ``vibap.policy_backend``, not each imported attribute.
    """

    package_parts = module_name.rsplit(".", 1)[0].split(".")
    if node.level:
        base = package_parts[: len(package_parts) - node.level + 1]
        module_parts = [] if node.module is None else node.module.split(".")
        resolved_module = ".".join(base + module_parts)
    else:
        resolved_module = node.module or ""

    resolved: set[str] = set()
    if node.module is None:
        for alias in node.names:
            resolved.add(f"{resolved_module}.{alias.name}" if resolved_module else alias.name)
    elif resolved_module:
        resolved.add(resolved_module)
    return resolved


def _target_edges() -> dict[str, set[str]]:
    edges: dict[str, set[str]] = {module: set() for module in TARGET_MODULES}
    for module_name, path in TARGET_MODULES.items():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imported_modules: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_modules.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported_modules.update(_resolve_import_from(module_name, node))

        for imported in imported_modules:
            if imported.startswith("vibap.backends."):
                edges[module_name].add("vibap.backends")
            for target in TARGET_MODULES:
                if imported == target or imported.startswith(f"{target}."):
                    edges[module_name].add(target)
        edges[module_name].discard(module_name)
    return edges


def _cycles(edges: dict[str, set[str]]) -> list[tuple[str, ...]]:
    cycles: list[tuple[str, ...]] = []

    def visit(start: str, current: str, path: list[str]) -> None:
        for next_module in edges[current]:
            if next_module == start:
                cycles.append(tuple([*path, next_module]))
            elif next_module not in path:
                visit(start, next_module, [*path, next_module])

    for module_name in sorted(edges):
        visit(module_name, module_name, [module_name])

    unique: dict[tuple[str, ...], tuple[str, ...]] = {}
    for cycle in cycles:
        cycle_body = cycle[:-1]
        rotations = [cycle_body[index:] + cycle_body[:index] for index in range(len(cycle_body))]
        unique[min(rotations)] = cycle
    return sorted(unique.values())


def test_policy_backend_has_no_static_concrete_backend_imports() -> None:
    edges = _target_edges()
    assert edges["vibap.policy_backend"].isdisjoint(
        {
            "vibap.backends",
            "vibap.backends.native",
            "vibap.backends.forbid_rules",
            "vibap.backends.cedar",
        }
    )


def test_policy_cluster_static_import_graph_is_acyclic() -> None:
    assert _cycles(_target_edges()) == []


def test_builtin_backend_bootstrap_still_restores_after_registry_clear() -> None:
    from vibap.policy_backend import clear_registry, get_backend

    clear_registry()
    try:
        assert get_backend("native").name == "native"
        assert get_backend("forbid_rules").name == "forbid_rules"
    finally:
        clear_registry()


def test_cedar_backend_bootstrap_preserves_optional_dependency_boundary() -> None:
    from vibap.policy_backend import clear_registry, get_backend

    clear_registry()
    try:
        try:
            backend = get_backend("cedar")
        except KeyError:
            pytest.skip("cedar optional dependency is unavailable")
        else:
            assert backend.name == "cedar"
    finally:
        clear_registry()
