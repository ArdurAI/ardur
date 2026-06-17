"""Native Messaging compatibility layer for Ardur Personal Hub.

The browser extension can talk to the Hub directly over loopback HTTP. This
module exists for browser deployments that require Chrome/Firefox Native
Messaging and for backwards-compatible examples. It forwards observations into
the same Hub API instead of issuing an independent receipt format.
"""

from __future__ import annotations

import json
import struct
import sys
from pathlib import Path
from typing import BinaryIO, Any

from .personal_hub import DEFAULT_HUB_URL, hub_request, _hub_setup_failure_flags

HOST_OBSERVATION_TYPE = "ardur.personal.host_observation.v0.1"
NATIVE_HOST_NAME = "dev.ardur.personal"


def build_native_host_manifest(
    host_path: str | Path,
    extension_id: str,
    *,
    browser: str = "chrome",
) -> dict[str, Any]:
    path = str(Path(host_path).expanduser().resolve())
    if browser == "firefox":
        return {
            "name": NATIVE_HOST_NAME,
            "description": "Ardur Personal Hub native messaging bridge",
            "path": path,
            "type": "stdio",
            "allowed_extensions": [extension_id],
        }
    return {
        "name": NATIVE_HOST_NAME,
        "description": "Ardur Personal Hub native messaging bridge",
        "path": path,
        "type": "stdio",
        "allowed_origins": [f"chrome-extension://{extension_id}/"],
    }


def handle_native_host_message(
    message: dict[str, Any],
    *,
    hub_url: str = DEFAULT_HUB_URL,
    hub_token: str | None = None,
    home: str | Path | None = None,
    storage_dir: str | Path | None = None,
    keys_dir: str | Path | None = None,
    caller_origin: str | None = None,
) -> dict[str, Any]:
    del storage_dir, keys_dir, caller_origin
    if message.get("type") != HOST_OBSERVATION_TYPE:
        return {"ok": False, "error": "unsupported native message type"}
    payload = message.get("hub_event")
    if not isinstance(payload, dict):
        receipt = message.get("browser_receipt") or {}
        page = receipt.get("page") if isinstance(receipt, dict) else {}
        event = receipt.get("event") if isinstance(receipt, dict) else {}
        payload = {
            "source": {
                "type": "browser",
                "app": "Browser extension",
                "origin": page.get("origin") if isinstance(page, dict) else None,
            },
            "session": {
                "id": page.get("tab_session_id") if isinstance(page, dict) else None,
                "title": message.get("title") or "",
            },
            "event": {
                "kind": "browser_native_observation",
                "action_class": event.get("action_class") if isinstance(event, dict) else "observe",
                "target": event.get("target") if isinstance(event, dict) else "browser",
                "content_digest": event.get("content_digest") if isinstance(event, dict) else None,
                "raw_content_included": False,
            },
        }
    response = hub_request("POST", "/v1/events/observe", payload, hub_url=hub_url, hub_token=hub_token, home=home)
    return native_host_response_with_next_steps(response)


def native_host_response_with_next_steps(response: dict[str, Any]) -> dict[str, Any]:
    """Return native-host output with safe local remediation hints when useful."""
    if response.get("ok"):
        return response

    steps = _native_host_next_steps_for_response(response)
    if not steps:
        return response
    return {**response, "next_steps": steps}


def _native_host_next_steps_for_response(response: dict[str, Any]) -> list[dict[str, str]]:
    hub_unavailable, token_problem = _hub_setup_failure_flags(response)
    if not hub_unavailable and not token_problem:
        return []

    steps: list[dict[str, str]] = []
    if hub_unavailable:
        steps.append(
            {
                "condition": "hub_unavailable",
                "action": "run_setup_if_needed",
                "command": "ardur setup --home <ardur-home>",
                "detail": (
                    "Create local Ardur Personal config and Hub token if setup has not run yet. "
                    "Do not paste raw tokens into shared logs."
                ),
            }
        )
        steps.append(
            {
                "condition": "hub_unavailable",
                "action": "start_personal_hub",
                "command": "ardur hub --home <ardur-home>",
                "detail": (
                    "Start the local loopback Ardur Personal Hub. If your config uses a "
                    "non-default endpoint, use host/port settings that match <hub-url>."
                ),
            }
        )

    if hub_unavailable or token_problem:
        steps.append(
            {
                "condition": "hub_token_required" if token_problem else "check_hub_token",
                "action": "supply_or_rotate_hub_token",
                "command": (
                    "ardur personal-native-host --once-json <native-message.json> "
                    "--home <ardur-home> --hub-url <hub-url> --hub-token <hub-token>"
                ),
                "detail": (
                    "Supply the existing local Hub token with --hub-token <hub-token> or "
                    "ARDUR_PERSONAL_HUB_TOKEN=<hub-token>; rotate it with "
                    "ardur setup --home <ardur-home> --rotate-token only when needed."
                ),
            }
        )

    steps.append(
        {
            "condition": "personal_native_host_failed",
            "action": "rerun_personal_native_host_or_doctor",
            "command": "ardur doctor --home <ardur-home> --hub-url <hub-url>",
            "detail": (
                "Confirm local setup before re-running ardur personal-native-host --once-json "
                "<native-message.json> --home <ardur-home> --hub-url <hub-url>. "
                "This guidance is local/no-key setup help only; it does not call live providers, "
                "prove provider-hidden actions, expose services beyond loopback, or broaden "
                "current Hub policy enforcement."
            ),
        }
    )
    return steps


def run_native_host(
    stdin: BinaryIO,
    stdout: BinaryIO,
    *,
    hub_url: str = DEFAULT_HUB_URL,
    hub_token: str | None = None,
    home: str | Path | None = None,
    storage_dir: str | Path | None = None,
    keys_dir: str | Path | None = None,
    caller_origin: str | None = None,
) -> None:
    while True:
        raw_len = stdin.read(4)
        if not raw_len:
            return
        if len(raw_len) != 4:
            return
        length = struct.unpack("<I", raw_len)[0]
        raw = stdin.read(length)
        try:
            message = json.loads(raw.decode("utf-8"))
            response = handle_native_host_message(
                message,
                hub_url=hub_url,
                hub_token=hub_token,
                home=home,
                storage_dir=storage_dir,
                keys_dir=keys_dir,
                caller_origin=caller_origin,
            )
        except Exception as exc:  # pragma: no cover - native host guardrail
            response = {"ok": False, "error": str(exc)}
        data = json.dumps(response).encode("utf-8")
        stdout.write(struct.pack("<I", len(data)))
        stdout.write(data)
        stdout.flush()


def main() -> int:
    run_native_host(sys.stdin.buffer, sys.stdout.buffer)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
