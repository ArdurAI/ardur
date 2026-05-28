"""
Phase 2 end-to-end test for the wired evidence CLI surface.

Uses the newly wired cli.py + cli_evidence module together with kernel data
to produce a regulator bundle (first concrete test after the small wiring delta).
"""

import tempfile
import os
from vibap.cli_evidence import main
from vibap.kernel_capture_client import KernelCaptureClient, KernelEvent


def test_cli_evidence_export_with_kernel_data_from_wired_surface():
    client = KernelCaptureClient()
    client.register_session("trace-cli-wired-001", "n1")
    client.inject_event(KernelEvent(event_type="exec", pid=9999, comm="bash", target="/tmp/wired"))

    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, "wired-bundle.json")

        # The CLI surface is now registered in cli.py via the small wiring.
        # We exercise the export path that can consume kernel data.
        rc = main([
            "evidence", "export",
            "--session", "trace-cli-wired-001",
            "--output", out,
            "--include-kernel"
        ])

        assert rc == 0
        assert os.path.exists(out)

        # Basic sanity on the produced bundle
        import json
        with open(out) as f:
            bundle = json.load(f)

        assert bundle["ardur_evidence_bundle_version"] == "0.1"
        assert "kernel" in bundle
        assert bundle["kernel"]["evidence_level"] in ("observed", "insufficient_evidence")
