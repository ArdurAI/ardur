"""Read-only posture detectors for agent trace artifacts."""

from .claude_detector import build_claude_posture_summary

__all__ = ["build_claude_posture_summary"]
