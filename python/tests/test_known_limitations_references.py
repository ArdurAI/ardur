"""Keep code references in the known-limitations contract tied to this tree."""

from __future__ import annotations

import ast
import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
DOCUMENT = REPO_ROOT / "docs" / "known-limitations.md"

CODE_SPAN_RE = re.compile(r"`([^`\n]+)`")
PYTHON_SYMBOL_RE = re.compile(
    r"^vibap\.[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+$",
)
GO_PACKAGE_SYMBOL_RE = re.compile(
    r"^(go/(?:cmd|pkg)/[A-Za-z0-9_./-]+)\.([A-Za-z_]\w*)$",
)
GO_DECLARATION_TEMPLATE = (
    r"(?m)^\s*(?:func\s+(?:\([^\n)]*\)\s*)?|type\s+|var\s+|const\s+){}\b"
)
REPOSITORY_PREFIXES = (".github/", "deploy/", "docs/", "go/", "python/")


def _code_spans() -> set[str]:
    return set(CODE_SPAN_RE.findall(DOCUMENT.read_text(encoding="utf-8")))


def _python_symbol_exists(reference: str) -> bool:
    _, module_name, *symbol_path = reference.split(".")
    module_path = REPO_ROOT / "python" / "vibap" / f"{module_name}.py"
    if not module_path.is_file():
        return False

    nodes: list[ast.stmt] = ast.parse(
        module_path.read_text(encoding="utf-8"),
        filename=str(module_path),
    ).body
    for symbol in symbol_path:
        match = next(
            (
                node
                for node in nodes
                if isinstance(
                    node,
                    (ast.AsyncFunctionDef, ast.ClassDef, ast.FunctionDef),
                )
                and node.name == symbol
            ),
            None,
        )
        if match is None:
            return False
        nodes = match.body if isinstance(match, ast.ClassDef) else []
    return True


def _go_symbol_exists(path: Path, symbol: str) -> bool:
    sources = [path] if path.is_file() else sorted(path.glob("*.go"))
    declaration = re.compile(GO_DECLARATION_TEMPLATE.format(re.escape(symbol)))
    return any(
        declaration.search(source.read_text(encoding="utf-8")) for source in sources
    )


def _repository_reference_error(reference: str) -> str | None:
    if "::" in reference:
        raw_path, symbol = reference.split("::", 1)
        path = REPO_ROOT / raw_path
        if not path.is_file():
            return f"missing file {raw_path}"
        if not _go_symbol_exists(path, symbol):
            return f"missing Go symbol {symbol} in {raw_path}"
        return None

    package_symbol = GO_PACKAGE_SYMBOL_RE.fullmatch(reference)
    if package_symbol:
        raw_path, symbol = package_symbol.groups()
        path = REPO_ROOT / raw_path
        if not path.is_dir():
            return f"missing Go package {raw_path}"
        if not _go_symbol_exists(path, symbol):
            return f"missing Go symbol {symbol} in {raw_path}"
        return None

    if reference.startswith("cmd/"):
        path = REPO_ROOT / "go" / reference
    elif reference.startswith(REPOSITORY_PREFIXES):
        path = REPO_ROOT / reference
    elif "/" not in reference and reference.endswith(".md"):
        path = DOCUMENT.parent / reference
    else:
        return None

    if not path.exists():
        return f"missing repository path {reference}"
    return None


def test_qualified_python_symbols_resolve() -> None:
    references = sorted(filter(PYTHON_SYMBOL_RE.fullmatch, _code_spans()))
    missing = [
        reference for reference in references if not _python_symbol_exists(reference)
    ]

    assert len(references) >= 10, "qualified Python reference discovery became vacuous"
    assert not missing, f"stale qualified Python references: {missing}"


def test_repository_paths_and_go_symbols_resolve() -> None:
    checked: dict[str, str] = {}
    for reference in sorted(_code_spans()):
        error = _repository_reference_error(reference)
        if error is not None:
            checked[reference] = error

    candidate_count = sum(
        1
        for reference in _code_spans()
        if reference.startswith((*REPOSITORY_PREFIXES, "cmd/"))
        or ("/" not in reference and reference.endswith(".md"))
    )
    assert candidate_count >= 15, "repository reference discovery became vacuous"
    assert not checked, f"stale repository references: {checked}"
