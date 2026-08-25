from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
PASSPORT_SOURCE = REPO_ROOT / "python" / "vibap" / "passport.py"
MAPPING_PATH = REPO_ROOT / "docs" / "specs" / "ardur-drp-mapping-v0.1.json"
PROFILE_SCHEMA_PATH = (
    REPO_ROOT / "docs" / "specs" / "ardur-drp-profile-v0.1.schema.json"
)


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


def _module_string_sequence_constant(tree: ast.Module, name: str) -> set[str]:
    """Resolve one required module-level literal sequence into unique keys."""

    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Name) or target.id != name:
            continue
        if not isinstance(node.value, (ast.List, ast.Tuple)):
            raise AssertionError(f"{name} must be a literal string sequence")
        values: list[str] = []
        for element in node.value.elts:
            if not isinstance(element, ast.Constant) or not isinstance(
                element.value, str
            ):
                raise AssertionError(f"{name} must be a literal string sequence")
            values.append(element.value)
        if not values:
            raise AssertionError(f"{name} must not be empty")
        if len(values) != len(set(values)):
            raise AssertionError(f"{name} must not contain duplicate entries")
        return set(values)
    raise AssertionError(f"missing module constant {name}")


def _string_dict_keys(node: ast.Dict, constants: dict[str, str]) -> set[str]:
    """Resolve static string keys while rejecting duplicate wire names."""

    keys: set[str] = set()
    for key in node.keys:
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            resolved_key = key.value
        elif isinstance(key, ast.Name) and key.id in constants:
            resolved_key = constants[key.id]
        else:
            raise AssertionError(
                "passport wire dictionaries must use literal string keys"
            )
        if resolved_key in keys:
            raise AssertionError(
                "passport wire dictionaries must not contain duplicate resolved keys"
            )
        keys.add(resolved_key)
    return keys


def _inherited_mic_claim_keys(tree: ast.Module) -> set[str]:
    """Recover the closed MIC inventory from its approved helper shape."""

    function = _function(tree, "_inherited_mic_conformance_claims")
    approved_claims = _module_string_sequence_constant(tree, "_DELEGATED_MIC_CLAIMS")
    nonempty_returns = 0

    for node in ast.walk(function):
        if not isinstance(node, ast.Return):
            continue
        value = node.value
        if isinstance(value, ast.Dict) and not value.keys and not value.values:
            continue
        if not isinstance(value, ast.DictComp) or len(value.generators) != 1:
            raise AssertionError(
                "_inherited_mic_conformance_claims may only return an empty "
                "dictionary or the approved claim-key comprehension"
            )
        generator = value.generators[0]
        if (
            generator.is_async
            or generator.ifs
            or not isinstance(generator.target, ast.Name)
            or not isinstance(generator.iter, ast.Name)
            or generator.iter.id != "_DELEGATED_MIC_CLAIMS"
            or not isinstance(value.key, ast.Name)
            or value.key.id != generator.target.id
        ):
            raise AssertionError(
                "_inherited_mic_conformance_claims non-empty return must be "
                "keyed solely from _DELEGATED_MIC_CLAIMS"
            )
        nonempty_returns += 1

    if nonempty_returns != 1:
        raise AssertionError(
            "_inherited_mic_conformance_claims must have exactly one approved "
            "non-empty return"
        )
    return approved_claims


def _derived_literal_dict_keys(
    tree: ast.Module,
    node: ast.Dict,
    constants: dict[str, str],
) -> set[str]:
    """Recover derived claims from the single approved literal dictionary."""

    unpack_indexes = [index for index, key in enumerate(node.keys) if key is None]
    if unpack_indexes != [0]:
        raise AssertionError(
            "derive_child_passport extra_claims must start with exactly one "
            "approved MIC inheritance unpack"
        )
    inherited = node.values[0]
    if (
        not isinstance(inherited, ast.Call)
        or not isinstance(inherited.func, ast.Name)
        or inherited.func.id != "_inherited_mic_conformance_claims"
        or len(inherited.args) != 1
        or not isinstance(inherited.args[0], ast.Name)
        or inherited.args[0].id != "parent"
        or inherited.keywords
    ):
        raise AssertionError(
            "derive_child_passport approved MIC inheritance unpack must be "
            "_inherited_mic_conformance_claims(parent)"
        )

    literal_claims = ast.Dict(keys=node.keys[1:], values=node.values[1:])
    claims = _string_dict_keys(literal_claims, constants)
    inherited_claims = _inherited_mic_claim_keys(tree)
    collisions = claims & inherited_claims
    if collisions:
        raise AssertionError(
            "derive_child_passport literal claims must not overwrite inherited "
            f"MIC claims: {sorted(collisions)}"
        )
    return claims | inherited_claims


def _issued_passport_claims(tree: ast.Module) -> set[str]:
    function = _function(tree, "issue_passport")
    constants = _module_string_constants(tree)
    claims: set[str] = set()

    for node in ast.walk(function):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "claims":
                    if not isinstance(node.value, ast.Dict):
                        raise AssertionError(
                            "issue_passport claims must be a literal dictionary"
                        )
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
    """Recover claims signed by the sole supported child-emission path."""

    function = _function(tree, "derive_child_passport")
    constants = _module_string_constants(tree)
    issue_passport_calls: list[ast.Call] = []
    for node in ast.walk(function):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Name) or node.func.id != "issue_passport":
            continue
        issue_passport_calls.append(node)

    if len(issue_passport_calls) != 1:
        raise AssertionError(
            "derive_child_passport must have exactly one direct issue_passport call"
        )
    extra_claim_keywords = [
        keyword
        for keyword in issue_passport_calls[0].keywords
        if keyword.arg == "extra_claims"
    ]
    if len(extra_claim_keywords) != 1:
        raise AssertionError(
            "derive_child_passport issue_passport call must carry exactly one "
            "extra_claims keyword"
        )
    keyword = extra_claim_keywords[0]
    if not isinstance(keyword.value, ast.Dict):
        raise AssertionError(
            "derive_child_passport extra_claims must be a literal dictionary"
        )
    return _derived_literal_dict_keys(tree, keyword.value, constants)


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
        (entry["source_surface"], entry["source_path"]) for entry in document["entries"]
    ]

    assert len(keys) == len(set(keys))
    assert document["status"] == "mapping-only"
    assert document["drp"]["formal_ietf_standing"] is False


def test_drp_mapping_required_extension_fields_match_profile_schema() -> None:
    mapping = json.loads(MAPPING_PATH.read_text(encoding="utf-8"))
    schema = json.loads(PROFILE_SCHEMA_PATH.read_text(encoding="utf-8"))

    assert set(mapping["profile_shape"]["ardur_required_fields"]) == set(
        schema["$defs"]["xArdur"]["required"]
    )


def test_drp_mapping_pins_mic_bundle_fail_closed_decisions() -> None:
    mapping = json.loads(MAPPING_PATH.read_text(encoding="utf-8"))
    mic_paths = {
        "conformance_profile",
        "receipt_policy",
        "tool_manifest_digest",
    }
    decisions = {
        entry["source_path"]: (entry["classification"], entry["drp_path"])
        for entry in mapping["entries"]
        if entry["source_surface"] == "legacy_python_passport"
        and entry["source_path"] in mic_paths
    }

    assert decisions == {
        "conformance_profile": ("out_of_scope", None),
        "receipt_policy": ("out_of_scope", None),
        "tool_manifest_digest": (
            "extension",
            "metadata.x-ardur.capabilityTokenRef.toolManifestDigest",
        ),
    }
    assert mapping["security_requirements"][
        "unprojected_mic_policy_bundle_rejected"
    ] == (
        "A source credential carrying conformance_profile or receipt_policy MUST NOT "
        "be emitted by this profile; the entire MIC bundle MUST be rejected and "
        "tool_manifest_digest MUST NOT be partially projected."
    )


@pytest.mark.parametrize(
    "extra_claims",
    [
        "{**unapproved_claims(parent), 'parent_token_hash': 'hash'}",
        (
            "{**_inherited_mic_conformance_claims(parent), "
            "**_inherited_mic_conformance_claims(parent), "
            "'parent_token_hash': 'hash'}"
        ),
    ],
)
def test_derived_claim_inventory_rejects_unknown_or_multiple_unpacks(
    extra_claims: str,
) -> None:
    tree = ast.parse(
        f"""
def derive_child_passport():
    return issue_passport(extra_claims={extra_claims})
"""
    )

    with pytest.raises(AssertionError, match="approved MIC inheritance unpack"):
        _derived_passport_claims(tree)


def test_derived_claim_inventory_rejects_multiple_issue_calls() -> None:
    tree = ast.parse(
        """
def derive_child_passport():
    if legacy:
        return issue_passport(extra_claims={"parent_token_hash": "hash"})
    return issue_passport()
"""
    )

    with pytest.raises(AssertionError, match="exactly one direct issue_passport call"):
        _derived_passport_claims(tree)


def test_derived_claim_inventory_rejects_unapproved_helper_keys() -> None:
    tree = ast.parse(
        """
_DELEGATED_MIC_CLAIMS = ("conformance_profile",)

def _inherited_mic_conformance_claims(parent_claims):
    if "conformance_profile" not in parent_claims:
        return {}
    return {"unregistered_claim": parent_claims["unregistered_claim"]}

def derive_child_passport():
    return issue_passport(
        extra_claims={
            **_inherited_mic_conformance_claims(parent),
            "parent_token_hash": "hash",
        }
    )
"""
    )

    with pytest.raises(AssertionError, match="approved claim-key comprehension"):
        _derived_passport_claims(tree)


def test_derived_claim_inventory_rejects_mic_claim_overwrite() -> None:
    tree = ast.parse(
        """
_DELEGATED_MIC_CLAIMS = ("conformance_profile",)

def _inherited_mic_conformance_claims(parent_claims):
    if "conformance_profile" not in parent_claims:
        return {}
    return {
        claim: parent_claims[claim] for claim in _DELEGATED_MIC_CLAIMS
    }

def derive_child_passport():
    return issue_passport(
        extra_claims={
            **_inherited_mic_conformance_claims(parent),
            "conformance_profile": "Delegation-Core",
        }
    )
"""
    )

    with pytest.raises(AssertionError, match="must not overwrite inherited MIC"):
        _derived_passport_claims(tree)


def test_derived_claim_inventory_rejects_duplicate_resolved_literal_keys() -> None:
    tree = ast.parse(
        """
DELEGATION_CHAIN_CLAIM = "delegation_chain"

def derive_child_passport():
    return issue_passport(
        extra_claims={
            **_inherited_mic_conformance_claims(parent),
            DELEGATION_CHAIN_CLAIM: child_chain,
            "delegation_chain": attacker_chain,
        }
    )
"""
    )

    with pytest.raises(AssertionError, match="duplicate resolved keys"):
        _derived_passport_claims(tree)


def test_derived_claim_inventory_rejects_duplicate_sequence_entries() -> None:
    tree = ast.parse(
        """
_DELEGATED_MIC_CLAIMS = ("conformance_profile", "conformance_profile")
"""
    )

    with pytest.raises(AssertionError, match="must not contain duplicate entries"):
        _module_string_sequence_constant(tree, "_DELEGATED_MIC_CLAIMS")
