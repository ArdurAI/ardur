"""Tests for vibap.backed_policy_store — file-backed policy persistence."""

from __future__ import annotations

import json
import threading

from vibap.backed_policy_store import FileBackedPolicyStore


def test_put_and_get_policies_by_mission_id(tmp_path):
    store = FileBackedPolicyStore(tmp_path)
    store.put_policies(
        mission_id="urn:ardur:mission:test-1",
        policies=[{"backend": "cedar", "policy": "permit()"}],
    )
    result = store.get_policies(mission_id="urn:ardur:mission:test-1")
    assert result is not None
    assert len(result) == 1
    assert result[0]["backend"] == "cedar"


def test_get_returns_none_for_unknown_mission(tmp_path):
    store = FileBackedPolicyStore(tmp_path)
    result = store.get_policies(mission_id="urn:ardur:mission:no-such")
    assert result is None


def test_empty_mission_id_fallback(tmp_path):
    store = FileBackedPolicyStore(tmp_path)
    fallback = [{"backend": "forbid_rules", "rule": "deny delete_file"}]
    store.put_policies(mission_id="", policies=fallback)

    result = store.get_policies(mission_id="urn:ardur:mission:unlisted")
    assert result is not None
    assert result[0]["backend"] == "forbid_rules"


def test_explicit_mission_overrides_fallback(tmp_path):
    store = FileBackedPolicyStore(tmp_path)
    store.put_policies(mission_id="", policies=[{"backend": "fallback"}])
    store.put_policies(
        mission_id="urn:ardur:mission:explicit",
        policies=[{"backend": "explicit"}],
    )

    result = store.get_policies(mission_id="urn:ardur:mission:explicit")
    assert result is not None
    assert result[0]["backend"] == "explicit"


def test_policies_persist_across_store_instances(tmp_path):
    store_a = FileBackedPolicyStore(tmp_path)
    store_a.put_policies(
        mission_id="urn:ardur:mission:persist",
        policies=[{"backend": "native"}],
    )

    store_b = FileBackedPolicyStore(tmp_path)
    result = store_b.get_policies(mission_id="urn:ardur:mission:persist")
    assert result is not None
    assert result[0]["backend"] == "native"


def test_atomic_write_does_not_corrupt_on_disk(tmp_path):
    store = FileBackedPolicyStore(tmp_path)
    store.put_policies(
        mission_id="urn:ardur:mission:safe",
        policies=[{"k": "v"}],
    )

    raw = tmp_path.joinpath("policies.json").read_text()
    data = json.loads(raw)
    assert "urn:ardur:mission:safe" in data

    # No .tmp file should be left behind after a successful write
    assert not tmp_path.joinpath("policies.json.tmp").exists()


def test_put_policies_overwrites_existing_entry(tmp_path):
    store = FileBackedPolicyStore(tmp_path)
    store.put_policies(
        mission_id="urn:ardur:mission:overwrite",
        policies=[{"v": 1}],
    )
    store.put_policies(
        mission_id="urn:ardur:mission:overwrite",
        policies=[{"v": 2}],
    )

    result = store.get_policies(mission_id="urn:ardur:mission:overwrite")
    assert result is not None
    assert result[0]["v"] == 2


def test_caches_data_to_avoid_repeated_disk_reads(tmp_path):
    store = FileBackedPolicyStore(tmp_path)
    store.put_policies(
        mission_id="urn:ardur:mission:cached",
        policies=[{"x": 1}],
    )

    call_count = 0
    original_load = store._load

    def counting_load():
        nonlocal call_count
        call_count += 1
        return original_load()

    store._load = counting_load
    store._cache = None  # force re-load on next access

    store.get_policies(mission_id="urn:ardur:mission:cached")
    store.get_policies(mission_id="urn:ardur:mission:cached")
    store.get_policies(mission_id="urn:ardur:mission:cached")

    assert call_count == 1  # cached after first load


def test_thread_safety_concurrent_puts(tmp_path):
    store = FileBackedPolicyStore(tmp_path)
    errors = []

    def writer(prefix: str):
        try:
            for i in range(20):
                store.put_policies(
                    mission_id=f"urn:ardur:mission:{prefix}-{i}",
                    policies=[{"prefix": prefix, "i": i}],
                )
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=writer, args=(f"t{t}",)) for t in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(errors) == 0
    # Each thread wrote 20 entries, 4 threads = 80 entries
    store._cache = None
    result = store.get_policies(mission_id="urn:ardur:mission:t0-0")
    assert result is not None
