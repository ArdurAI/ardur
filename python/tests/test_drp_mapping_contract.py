from __future__ import annotations

import ast
import json
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
PASSPORT_SOURCE = REPO_ROOT / "python" / "vibap" / "passport.py"
MAPPING_PATH = REPO_ROOT / "docs" / "specs" / "ardur-drp-mapping-v0.1.json"


def _function(tree: ast.Module, name: str) -> ast.FunctionDef:
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(f"missing function {name}")


def _module_string_constants(tree: ast.Module) -> dict[str, str]:
    constants: dict[str, str] = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if (
            isinstance(target, ast.Name)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            constants[target.id] = node.value.value
    return constants


def _string_dict_keys(node: ast.Dict, constants: dict[str, str]) -> set[str]:
    keys: set[str] = set()
    for key in node.keys:
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            keys.add(key.value)
            continue
        if isinstance(key, ast.Name) and key.id in constants:
            keys.add(constants[key.id])
            continue
        else:
            raise AssertionError("passport wire dictionaries must use literal string keys")
    return keys


def _issued_passport_claims(tree: ast.Module) -> set[str]:
    function = _function(tree, "issue_passport")
    constants = _module_string_constants(tree)
    claims: set[str] = set()

    for node in ast.walk(function):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "claims":
                    if not isinstance(node.value, ast.Dict):
                        raise AssertionError("issue_passport claims must be a literal dictionary")
                    claims.update(_string_dict_keys(node.value, constants))
                if (
                    isinstance(target, ast.Subscript)
                    and isinstance(target.value, ast.Name)
                    and target.value.id == "claims"
                    and isinstance(target.slice, ast.Constant)
                    and isinstance(target.slice.value, str)
                ):
                    claims.add(target.slice.value)
    return claims


def _derived_passport_claims(tree: ast.Module) -> set[str]:
    function = _function(tree, "derive_child_passport")
    constants = _module_string_constants(tree)
    for node in ast.walk(function):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Name) or node.func.id != "issue_passport":
            continue
        for keyword in node.keywords:
            if keyword.arg == "extra_claims":
                if not isinstance(keyword.value, ast.Dict):
                    raise AssertionError("derive_child_passport extra_claims must be literal")
                return _string_dict_keys(keyword.value, constants)
    raise AssertionError("missing derive_child_passport extra_claims")


def test_drp_mapping_covers_legacy_python_passport_claims() -> None:
    tree = ast.parse(PASSPORT_SOURCE.read_text(encoding="utf-8"))
    expected = _issued_passport_claims(tree) | _derived_passport_claims(tree)

    document = json.loads(MAPPING_PATH.read_text(encoding="utf-8"))
    actual = {
        entry["source_path"]
        for entry in document["entries"]
        if entry["source_surface"] == "legacy_python_passport"
    }

    assert actual == expected


def test_drp_mapping_has_no_duplicate_source_fields() -> None:
    document = json.loads(MAPPING_PATH.read_text(encoding="utf-8"))
    keys = [
        (entry["source_surface"], entry["source_path"])
        for entry in document["entries"]
    ]

    assert len(keys) == len(set(keys))
    assert document["status"] == "mapping-only"
    assert document["drp"]["formal_ietf_standing"] is False
