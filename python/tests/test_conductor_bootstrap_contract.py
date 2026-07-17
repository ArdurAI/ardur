"""Regression coverage for the Conductor bootstrap output contract."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
BOOTSTRAP = REPO_ROOT / "scripts" / "conductor-bootstrap.sh"
GRAPH_ARTIFACTS = (
    ".context/ardur-graph.json",
    ".context/ardur-graph.md",
    ".context/ardur-graph.mmd",
)
LOCAL_ARTIFACTS = (
    ".context/ARDUR_CONTEXT.md",
    *GRAPH_ARTIFACTS,
    ".context/skills/README.md",
)
AUTHORITATIVE_STARTUP_DOCS = (
    REPO_ROOT / "AGENTS.md",
    REPO_ROOT / "docs" / "agent-instructions" / "shared.md",
    REPO_ROOT / "docs" / "conductor-bootstrap.md",
)


def _section(document: str, heading: str) -> str:
    match = re.search(
        rf"^{re.escape(heading)}\n(?P<body>.*?)(?=^## |\Z)",
        document,
        flags=re.MULTILINE | re.DOTALL,
    )
    assert match is not None, f"missing section: {heading}"
    return match.group("body")


def _fixture_repo(
    tmp_path: Path,
    *,
    complete_graph: bool | None,
    empty_graph_artifact: str | None = None,
) -> Path:
    assert empty_graph_artifact in (None, "ardur-graph.md", "ardur-graph.mmd")
    assert empty_graph_artifact is None or complete_graph is True
    repo = tmp_path / "repo"
    scripts = repo / "scripts"
    scripts.mkdir(parents=True)
    shutil.copy2(BOOTSTRAP, scripts / BOOTSTRAP.name)
    (repo / ".gitignore").write_text(".context/\n", encoding="utf-8")
    if complete_graph is not None:
        graph_markdown = (
            "" if empty_graph_artifact == "ardur-graph.md" else "# Graph\n"
        )
        graph_mermaid = (
            "" if empty_graph_artifact == "ardur-graph.mmd" else "graph TD\n"
        )
        (scripts / "build-knowledge-graph.py").write_text(
            f"""\
import json
import sys
from pathlib import Path

output = Path(sys.argv[sys.argv.index("--output-dir") + 1])
output.mkdir(parents=True, exist_ok=True)
(output / "ardur-graph.json").write_text(
    json.dumps({{
        "counts": {{"nodes": 1, "edges": 0, "nodes_by_type": {{"test": 1}}}},
        "repo": {{
            "indexed_file_count": 1,
            "tracked_file_count": 2,
            "untracked_file_count": 0,
        }},
    }}),
    encoding="utf-8",
)
if {complete_graph!r}:
    (output / "ardur-graph.md").write_text(
        {graph_markdown!r},
        encoding="utf-8",
    )
    (output / "ardur-graph.mmd").write_text(
        {graph_mermaid!r},
        encoding="utf-8",
    )
""",
            encoding="utf-8",
        )
    subprocess.run(("git", "init", "--quiet"), cwd=repo, check=True)
    subprocess.run(("git", "add", "--all"), cwd=repo, check=True)
    subprocess.run(
        (
            "git",
            "-c",
            "user.name=Bootstrap Contract Test",
            "-c",
            "user.email=bootstrap-contract@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "fixture",
        ),
        cwd=repo,
        check=True,
    )
    return repo


def _run_fixture_bootstrap(repo: Path) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment.update(
        {
            "ARDUR_BASE_REF": "HEAD",
            "ARDUR_RELEASE_REF": "HEAD",
            "PYTHON_BIN": sys.executable,
        }
    )
    return subprocess.run(
        (str(repo / "scripts" / BOOTSTRAP.name),),
        cwd=repo,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )


def test_no_generator_bootstrap_only_advertises_existing_artifacts(
    tmp_path: Path,
) -> None:
    """Successful fallback bootstrap output must not require absent graph files."""

    repo = _fixture_repo(tmp_path, complete_graph=None)
    context_dir = tmp_path / "generated" / ".context"
    context_dir.mkdir(parents=True)
    for filename in ("ardur-graph.json", "ardur-graph.md", "ardur-graph.mmd"):
        (context_dir / filename).write_text("stale graph\n", encoding="utf-8")
    environment = os.environ.copy()
    environment.update(
        {
            "ARDUR_BASE_REF": "HEAD",
            "ARDUR_RELEASE_REF": "HEAD",
            "ARDUR_CONTEXT_DIR": str(context_dir),
        }
    )

    completed = subprocess.run(
        (str(repo / "scripts" / BOOTSTRAP.name),),
        cwd=repo,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    context = (context_dir / "ARDUR_CONTEXT.md").read_text(encoding="utf-8")
    required_reading = _section(context, "## Required Reading Order")
    graph_status = _section(context, "## Generated Graph")
    generated_files = _section(context, "## Generated Files")

    assert "unavailable" in graph_status.lower()
    assert "live source files and workflow files" in graph_status
    for relative in GRAPH_ARTIFACTS:
        assert relative not in required_reading
        assert relative not in generated_files
        assert not (context_dir / Path(relative).name).exists()

    advertised = re.findall(r"^- `(?P<path>[^`]+)`$", generated_files, re.MULTILINE)
    assert advertised
    for relative in advertised:
        path = Path(relative)
        assert path.is_absolute()
        assert path.is_file(), relative


def test_bootstrap_artifacts_are_local_only() -> None:
    """Every possible bootstrap output must remain excluded from normal staging."""

    for relative in LOCAL_ARTIFACTS:
        completed = subprocess.run(
            ("git", "check-ignore", "--quiet", relative),
            cwd=REPO_ROOT,
            check=False,
        )
        assert completed.returncode == 0, relative


def test_authoritative_startup_docs_make_graph_reads_conditional() -> None:
    """The public startup contract must describe both graph availability paths."""

    for path in AUTHORITATIVE_STARTUP_DOCS:
        content = path.read_text(encoding="utf-8")
        assert "Generated Graph" in content, path
        assert "`available`" in content, path
        assert "`unavailable`" in content, path
        assert "optional" in content.lower(), path


def test_present_graph_builder_must_produce_the_complete_artifact_set(
    tmp_path: Path,
) -> None:
    """A partial graph build must fail before success-looking context is emitted."""

    repo = _fixture_repo(tmp_path, complete_graph=False)
    stale_context = repo / ".context" / "ARDUR_CONTEXT.md"
    stale_context.parent.mkdir()
    stale_context.write_text("# stale successful context\n", encoding="utf-8")
    completed = _run_fixture_bootstrap(repo)

    assert completed.returncode != 0
    assert "graph builder did not produce required artifact" in completed.stderr
    assert not (repo / ".context" / "ARDUR_CONTEXT.md").exists()


def test_present_graph_builder_must_produce_nonempty_artifacts(
    tmp_path: Path,
) -> None:
    """An empty graph artifact must fail before success context is emitted."""

    repo = _fixture_repo(
        tmp_path,
        complete_graph=True,
        empty_graph_artifact="ardur-graph.mmd",
    )
    completed = _run_fixture_bootstrap(repo)

    assert completed.returncode != 0
    assert "graph builder did not produce required artifact" in completed.stderr
    assert not (repo / ".context" / "ARDUR_CONTEXT.md").exists()


def test_complete_graph_builder_advertises_every_generated_artifact(
    tmp_path: Path,
) -> None:
    """The graph-present path must list only the complete readable artifact set."""

    repo = _fixture_repo(tmp_path, complete_graph=True)
    completed = _run_fixture_bootstrap(repo)

    assert completed.returncode == 0, completed.stderr
    context = (repo / ".context" / "ARDUR_CONTEXT.md").read_text(encoding="utf-8")
    required_reading = _section(context, "## Required Reading Order")
    graph_status = _section(context, "## Generated Graph")
    generated_files = _section(context, "## Generated Files")

    assert "Status: available" in graph_status
    for relative in GRAPH_ARTIFACTS:
        assert relative in generated_files
        assert (repo / relative).is_file()
    assert ".context/ardur-graph.md" in required_reading
    assert ".context/ardur-graph.json" in required_reading
