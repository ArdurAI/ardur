from __future__ import annotations

import json

from vibap.personal_firewall import run_personal_firewall_demo


def test_provider_free_personal_firewall_demo_is_verified_and_private(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("ARDUR_MISSION_PASSPORT", "poisoned-parent-token")
    monkeypatch.setenv("ARDUR_CC_HOOK_DIR", str(tmp_path / "outside-chain"))
    result = run_personal_firewall_demo(temp_parent=tmp_path, emit=False)

    assert result["ok"] is True
    assert [item["result"] for item in result["decisions"]] == [
        "ASK",
        "DENY",
        "DENY",
        "DENY",
    ]
    assert result["receipts"] == {
        "count": 4,
        "chains": 1,
        "verified": True,
        "readable_summaries": True,
    }
    assert result["cost_boundary"]["monetary_cost"] == (
        "unavailable_without_signed_adapter_data"
    )
    assert result["temporary_state_removed"] is True
    assert str(tmp_path) not in json.dumps(result, sort_keys=True)
    assert list(tmp_path.iterdir()) == []
