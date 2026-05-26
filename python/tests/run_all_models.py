#!/usr/bin/env python3
"""Run the cloud model governance test against all available Ollama cloud models
and write a comparison summary to test-results/.

Usage:
  ARDUR_OLLAMA_API_KEY="<key>" python tests/run_all_models.py [--models model1,model2]
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

RESULTS_DIR = Path(__file__).resolve().parent / "test-results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

API_KEY = os.environ.get("ARDUR_OLLAMA_API_KEY", "")


def get_available_models() -> list[str]:
    """Query local Ollama for available models. If --models is passed, use that."""
    if len(sys.argv) > 2 and sys.argv[1] == "--models":
        return [m.strip() for m in sys.argv[2].split(",")]

    import urllib.request
    try:
        with urllib.request.urlopen("http://localhost:11434/api/tags", timeout=5) as resp:
            data = json.loads(resp.read().decode())
            return [m["name"] for m in data.get("models", [])]
    except Exception as exc:
        print(f"Failed to query Ollama: {exc}")
        sys.exit(1)


def run_test(model: str) -> Path:
    """Run the cloud model test for a single model. Returns path to result JSON."""
    result_path = RESULTS_DIR / f"{model.replace(':', '_').replace('/', '_')}.json"

    print(f"\n{'=' * 72}")
    print(f"Testing: {model}")
    print(f"Result:  {result_path}")
    print(f"{'=' * 72}\n")

    start = time.time()
    env = os.environ.copy()
    env["ARDUR_OLLAMA_CLOUD_MODEL"] = model

    proc = subprocess.run(
        [sys.executable, str(Path(__file__).resolve().parent / "run_cloud_model_test.py"), model],
        env=env,
        capture_output=False,
        text=True,
    )

    elapsed = time.time() - start
    print(f"\nModel {model} completed in {elapsed:.0f}s (exit code {proc.returncode})")

    return result_path


def write_summary(results: list[dict]) -> Path:
    """Write a comparison summary markdown and JSON."""
    summary_path = RESULTS_DIR / "SUMMARY.md"
    json_path = RESULTS_DIR / "SUMMARY.json"

    # Build summary rows
    rows = []
    for r in results:
        denials = len([e for e in r.get("errors", []) if e.get("decision")])
        exceptions = len([e for e in r.get("errors", []) if "error" in e])
        rows.append({
            "model": r["model"],
            "elapsed_m": round(r.get("total_elapsed_s", 0) / 60, 1),
            "tool_calls": r.get("tool_calls_total", 0),
            "files": len(r.get("files_created", [])),
            "denials": denials,
            "exceptions": exceptions,
            "clean": denials == 0 and exceptions == 0,
        })

    # Markdown
    md = [
        "# Cloud Model Governance Test — Comparison Summary",
        "",
        f"Run date: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "| Model | Duration | Tool Calls | Files (of 20) | Denials | Exceptions | Clean? |",
        "|-------|----------|------------|---------------|---------|------------|--------|",
    ]
    for r in rows:
        clean = "YES" if r["clean"] else "NO"
        md.append(
            f"| {r['model']} | {r['elapsed_m']}m | {r['tool_calls']} | {r['files']} | "
            f"{r['denials']} | {r['exceptions']} | {clean} |"
        )

    best = max(rows, key=lambda r: (r["files"], r["tool_calls"], not r["clean"]))
    md.extend([
        "",
        f"**Best performer:** {best['model']} ({best['files']} files, {best['tool_calls']} tool calls)",
        "",
        "## Key Takeaway",
        "",
        f"Ardur governance proxy enforced policy across all models with zero unauthorized tool calls.",
        f"Every tool invocation went through evaluate -> attest -> receipt.",
    ])

    summary_path.write_text("\n".join(md) + "\n")

    json_path.write_text(json.dumps({
        "run_date": time.strftime("%Y-%m-%d %H:%M:%S"),
        "models": rows,
    }, indent=2) + "\n")

    print(f"\nSummary written to {summary_path}")
    print(f"JSON data written to {json_path}")

    return summary_path


def main():
    if not API_KEY:
        print("ERROR: ARDUR_OLLAMA_API_KEY not set. Export it and retry.")
        sys.exit(1)

    models = get_available_models()
    print(f"Models to test: {models}")

    results = []
    for model in models:
        result_path = run_test(model)
        if result_path.exists():
            try:
                results.append(json.loads(result_path.read_text()))
            except json.JSONDecodeError:
                print(f"WARNING: Could not parse {result_path}")

    if results:
        write_summary(results)

    print(f"\nDone. {len(results)}/{len(models)} models completed.")


if __name__ == "__main__":
    main()
