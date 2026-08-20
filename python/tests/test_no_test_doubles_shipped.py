"""Architecture test: no test double may ship inside the ``vibap`` package.

The Python analogue of ``go/internal/linkgraph``'s link-graph rule. Go can
ask the compiler what a binary actually links; Python has no link step, so
the equivalent structural question is "what does the wheel contain?" —
``pyproject.toml`` has ``[tool.setuptools.packages.find] include = ["vibap*"]``,
so every module under ``vibap/`` ships and ``python/tests/`` does not. A
public name declared under ``vibap/`` is a name an integrator can import at
runtime from a plain ``pip install ardur``.

Why that matters more here than "mocks are untidy": the doubles this rule
was written for — ``make_mock_svid_bundle`` and ``make_mock_trust_bundle``,
now in ``tests/spiffe_doubles.py`` — mint every key deterministically from a
SHA-256 over a constant label and the caller's SPIFFE ID. The private half of
the mock trust anchor is therefore computable by anyone who can read the
source. They also produce a *complete and well-formed* X.509-SVID, JWT-SVID
and trust bundle, so nothing downstream would notice: wire
``make_mock_trust_bundle`` into a real configuration and you have installed a
trust root whose signing key is public knowledge, and every SVID it validates
is forgeable by anyone. Ardur's whole claim is that a receipt proves what an
agent did; a forgeable trust root turns that proof into an assertion.

No production code ever called them, so this was a latent hazard rather than
an exploited vulnerability. Keeping them out of the shipped package is the
structural form of the rule. A comment asking people not to import a mock
is not.

This lives as a pytest test rather than a CI step so that it runs everywhere
``pytest tests/`` runs — CI, ``make test-python``, and a developer's
checkout — with no workflow wiring to keep in sync. (The repo's CI ``ruff``
step uses an explicit path allowlist; a lint-based rule would silently not
apply to most of the package.)
"""

from __future__ import annotations

import ast
import pathlib
import re

import vibap


# Matches a name that marks a declaration as a test double, with or without a
# factory prefix: mock_x, MockClient, FakeIssuer, make_mock_svid_bundle,
# build_stub_policy, new_dummy_receipt. Anchored at the start so that a name
# that merely contains the word (``demockingbird``, ``remote_stub_count``)
# does not trip it, and applied only to module-level declarations so a local
# variable named ``mock_response`` inside a function is untouched.
TEST_DOUBLE_NAME = re.compile(r"^(make_|new_|build_)?(mock|fake|stub|dummy)", re.IGNORECASE)

_DECLARATIONS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)

REMEDY = """
    A public test double is declared in the shipped `vibap` package.

    `pyproject.toml` ships `vibap*` and nothing else, so this name is
    importable at runtime by anyone who ran `pip install ardur`. The SPIFFE
    doubles this rule was written for mint deterministic, attacker-derivable
    key material into a trust-root path — a caller who wires one in installs
    a trust anchor whose private key is public knowledge, and the signed
    artifacts downstream still look valid.

    Move the double to `python/tests/spiffe_doubles.py` (or another module
    under `python/tests/`, which is not packaged), and import it from the
    tests that need it. If the name is genuine production code that merely
    reads as a double, rename it — the name is what an integrator sees."""


def _shipped_modules() -> list[pathlib.Path]:
    """Every ``.py`` file that the wheel carries."""

    package_root = pathlib.Path(vibap.__file__).resolve().parent
    return sorted(package_root.rglob("*.py"))


def test_no_public_test_double_is_declared_in_the_shipped_package() -> None:
    modules = _shipped_modules()

    # Non-vacuity: an empty walk would pass silently and forever. If the
    # package layout moves out from under this test, that is a failure of the
    # test, not a clean bill of health.
    assert modules, (
        "walked 0 modules under "
        f"{pathlib.Path(vibap.__file__).resolve().parent} — refusing to pass "
        "vacuously; the shipped-package layout this test walks has moved"
    )

    findings: list[str] = []
    for module in modules:
        tree = ast.parse(module.read_text(encoding="utf-8"), filename=str(module))
        for node in tree.body:
            if not isinstance(node, _DECLARATIONS):
                continue
            if node.name.startswith("_"):
                # Private by convention: not part of the importable surface an
                # integrator is offered, and not what this rule is about.
                continue
            if TEST_DOUBLE_NAME.match(node.name):
                findings.append(
                    f"  {module}:{node.lineno}: "
                    f"{type(node).__name__} {node.name}"
                )

    assert not findings, (
        f"{len(findings)} public test double(s) declared in the shipped vibap "
        f"package (walked {len(modules)} modules):\n"
        + "\n".join(findings)
        + "\n"
        + REMEDY
    )


def test_the_detector_itself_flags_and_spares_the_right_names() -> None:
    """Positive/negative controls, so a broken regex cannot pass vacuously."""

    should_flag = [
        "make_mock_svid_bundle",
        "make_mock_trust_bundle",
        "mock_client",
        "MockIssuer",
        "FakeTrustBundle",
        "fake_receipt",
        "StubPolicyStore",
        "stub_verifier",
        "DummyProxy",
        "new_fake_session",
        "build_stub_policy",
    ]
    should_spare = [
        "fetch_svid",
        "verify_jwt_svid",
        "load_trust_bundle",
        "SvidBundle",
        # Contains a needle but does not start with one.
        "remote_stub_count",
        "demockingbird",
        "make_passport",
    ]

    missed = [name for name in should_flag if not TEST_DOUBLE_NAME.match(name)]
    assert not missed, f"detector failed to flag test-double names: {missed}"

    false_positives = [name for name in should_spare if TEST_DOUBLE_NAME.match(name)]
    assert not false_positives, (
        f"detector flagged legitimate production names: {false_positives}"
    )
