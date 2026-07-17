"""Regression coverage for the required Markdown link-check policy."""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE_DOC = REPO_ROOT / "docs/research/epic-b-performance-fp-budget.md"
MIRROR_DOC = (
    REPO_ROOT / "site/content/source/docs/research/epic-b-performance-fp-budget.md"
)
LINK_WORKFLOW = REPO_ROOT / ".github/workflows/link-check.yml"

FRAGILE_UBUNTU_MIRROR = (
    "https://manpages.ubuntu.com/manpages/focal/en/man8/execsnoop-bpfcc.8.html"
)
IMMUTABLE_UPSTREAM_SOURCE = (
    "https://github.com/iovisor/bcc/blob/"
    "6ebeb451656d75e599dc34af12b479c02a3fc041/man/man8/execsnoop.8"
)


def test_exec_rate_citation_uses_immutable_upstream_source() -> None:
    """The required gate must not depend on the redundant timeout-prone mirror."""

    for path in (SOURCE_DOC, MIRROR_DOC):
        content = path.read_text(encoding="utf-8")
        assert FRAGILE_UBUNTU_MIRROR not in content
        assert content.count(IMMUTABLE_UPSTREAM_SOURCE) == 2


def test_required_link_check_keeps_timeouts_fail_closed() -> None:
    """Reliability fixes must preserve the required check instead of hiding failures."""

    workflow = LINK_WORKFLOW.read_text(encoding="utf-8")
    normalized_workflow = workflow.replace("\\.", ".")
    assert "--accept-timeouts" not in workflow
    assert "manpages.ubuntu.com" not in normalized_workflow
    assert 'if [ "$LYCHEE" != "success" ]' in workflow
