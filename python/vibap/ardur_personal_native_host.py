"""Native Messaging compatibility layer for Ardur Personal Hub.

The browser extension can talk to the Hub directly over loopback HTTP. This
module exists for browser deployments that require Chrome/Firefox Native
Messaging and for backwards-compatible examples. It forwards observations into
the same Hub API instead of issuing an independent receipt format.
"""

from __future__ import annotations

import json
import os
import re
import struct
import sys
from pathlib import Path
from typing import BinaryIO, Any

from .personal_hub import DEFAULT_HUB_URL, hub_request, _hub_setup_failure_flags

HOST_OBSERVATION_TYPE = "ardur.personal.host_observation.v0.1"
NATIVE_HOST_NAME = "dev.ardur.personal"
_CHROME_EXTENSION_ID_RE = re.compile(r"^[a-p]{32}$")


class NativeHostManifestValidationError(ValueError):
    """Raised when manifest generation would emit a browser-rejected manifest."""

    def __init__(self, response: dict[str, Any]):
        super().__init__(str(response.get("message", "native host manifest input invalid")))
        self.response = response


def _native_host_manifest_extension_id_next_steps() -> list[dict[str, str]]:
    condition = "personal_native_manifest_extension_id_invalid"
    return [
        {
            "condition": condition,
            "action": "check_browser_extension_id",
            "command": (
                "ardur personal-native-manifest --host-path <native-host-path> "
                "--extension-id <extension-id> --browser <browser>"
            ),
            "detail": (
                "Use the installed browser extension id: Chrome-family ids are 32 lowercase "
                "characters from a-p; Firefox add-on ids must be non-empty. Keep local host "
                "paths and private development ids out of shared logs."
            ),
        },
        {
            "condition": condition,
            "action": "rerun_manifest_generation",
            "command": (
                "ardur personal-native-manifest --host-path <native-host-path> "
                "--extension-id <extension-id> --browser <browser>"
            ),
            "detail": (
                "Regenerate the Native Messaging manifest locally after correcting the id. "
                "This is setup guidance only; it does not prove browser-store deployment "
                "or native-host installation."
            ),
        },
    ]


def _native_host_manifest_host_path_next_steps() -> list[dict[str, str]]:
    condition = "personal_native_manifest_host_path_invalid"
    return [
        {
            "condition": condition,
            "action": "check_native_host_path",
            "command": "test -f <native-host-path> && test -x <native-host-path>",
            "detail": (
                "Use the executable Ardur Personal Native Messaging host file. Empty values, "
                "directories, missing files, and non-executable files are rejected before "
                "manifest emission."
            ),
        },
        {
            "condition": condition,
            "action": "rerun_manifest_generation",
            "command": (
                "ardur personal-native-manifest --host-path <native-host-path> "
                "--extension-id <extension-id> --browser <browser>"
            ),
            "detail": (
                "Regenerate the Native Messaging manifest locally after selecting a runnable "
                "host file. This is setup guidance only; it does not prove browser-store "
                "deployment or native-host installation."
            ),
        },
    ]


def _native_host_unsupported_message_type_next_steps() -> list[dict[str, str]]:
    condition = "personal_native_host_message_type_unsupported"
    return [
        {
            "condition": condition,
            "action": "create_supported_native_message",
            "command": "ardur personal-native-host --once-json <native-message.json> --home <ardur-home> --hub-url <hub-url>",
            "detail": (
                "Create a local Native Messaging JSON object with the supported Ardur "
                "Personal host observation type before sending it through --once-json or "
                "browser Native Messaging. Keep raw payloads, local paths, and Hub tokens "
                "out of shared logs and reports."
            ),
        },
        {
            "condition": condition,
            "action": "rerun_personal_native_host_or_doctor",
            "command": "ardur doctor --home <ardur-home> --hub-url <hub-url>",
            "detail": (
                "After the message type is supported, check local Ardur Personal setup with "
                "doctor or rerun ardur personal-native-host --once-json <native-message.json>. "
                "This guidance is local/no-key input recovery only; it does not prove "
                "browser-store deployment or Native Messaging installation."
            ),
        },
    ]


def native_host_unsupported_message_type_failure_response() -> dict[str, Any]:
    """Return stable guidance for unsupported native messages without echoing payloads."""
    condition = "personal_native_host_message_type_unsupported"
    return {
        "ok": False,
        "error": condition,
        "condition": condition,
        "message": "Native Messaging message type is not supported by the Ardur Personal host.",
        "detail": (
            f"Native host messages must use type {HOST_OBSERVATION_TYPE}; unsupported "
            "message types fail closed before any Hub forwarding."
        ),
        "next_steps": _native_host_unsupported_message_type_next_steps(),
    }


def native_host_manifest_extension_id_failure_response(browser: str) -> dict[str, Any]:
    """Return structured manifest-id validation guidance without echoing raw input."""
    condition = "personal_native_manifest_extension_id_invalid"
    browser_key = browser.strip().lower()
    if browser_key == "firefox":
        detail = "Firefox Native Messaging extension ids must be non-empty after trimming whitespace."
    else:
        detail = (
            "Chrome-family Native Messaging extension ids must be exactly 32 lowercase "
            "characters using only letters a through p."
        )
    return {
        "ok": False,
        "error": condition,
        "condition": condition,
        "message": "Native Messaging manifest extension id is invalid for the selected browser.",
        "detail": detail,
        "next_steps": _native_host_manifest_extension_id_next_steps(),
    }


def native_host_manifest_host_path_failure_response() -> dict[str, Any]:
    """Return structured host-path validation guidance without echoing raw input."""
    condition = "personal_native_manifest_host_path_invalid"
    return {
        "ok": False,
        "error": condition,
        "condition": condition,
        "message": "Native Messaging manifest host path is not a runnable host file.",
        "detail": (
            "The host path must identify an existing executable file for the Ardur Personal "
            "Native Messaging host. Empty values, directories, missing files, and "
            "non-executable files fail closed before a manifest is emitted."
        ),
        "next_steps": _native_host_manifest_host_path_next_steps(),
    }


def validate_native_host_manifest_extension_id(extension_id: str, browser: str) -> None:
    """Fail closed before emitting browser-rejected Native Messaging manifests."""
    browser_key = browser.strip().lower()
    if browser_key == "firefox":
        if not extension_id.strip():
            raise NativeHostManifestValidationError(
                native_host_manifest_extension_id_failure_response(browser)
            )
        return

    if not _CHROME_EXTENSION_ID_RE.fullmatch(extension_id):
        raise NativeHostManifestValidationError(
            native_host_manifest_extension_id_failure_response(browser)
        )


def validate_native_host_manifest_host_path(host_path: str | Path) -> Path:
    """Return a resolved runnable host file path or fail closed before manifest emission."""
    raw_host_path = str(host_path)
    if not raw_host_path.strip():
        raise NativeHostManifestValidationError(native_host_manifest_host_path_failure_response())

    try:
        path = Path(raw_host_path).expanduser().resolve()
    except (OSError, RuntimeError):
        raise NativeHostManifestValidationError(native_host_manifest_host_path_failure_response()) from None

    if not path.is_file() or not os.access(path, os.X_OK):
        raise NativeHostManifestValidationError(native_host_manifest_host_path_failure_response())
    return path


def build_native_host_manifest(
    host_path: str | Path,
    extension_id: str,
    *,
    browser: str = "chrome",
) -> dict[str, Any]:
    validate_native_host_manifest_extension_id(extension_id, browser)
    path = str(validate_native_host_manifest_host_path(host_path))
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
        return native_host_unsupported_message_type_failure_response()
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


def _native_host_framed_input_next_steps(condition: str) -> list[dict[str, str]]:
    return [
        {
            "condition": condition,
            "action": "validate_native_message_json",
            "command": "ardur personal-native-host --once-json <native-message.json> --home <ardur-home> --hub-url <hub-url>",
            "detail": (
                "Validate a local native-message JSON object before sending it through "
                "browser Native Messaging. Keep raw payloads, local paths, and Hub tokens "
                "out of shared logs and reports."
            ),
        },
        {
            "condition": condition,
            "action": "rerun_personal_native_host_or_doctor",
            "command": "ardur doctor --home <ardur-home> --hub-url <hub-url>",
            "detail": (
                "After the framed message is valid JSON, check local Ardur Personal setup "
                "with doctor or rerun ardur personal-native-host --once-json "
                "<native-message.json>."
            ),
        },
    ]


def native_host_framed_input_failure_response(exc: Exception) -> dict[str, Any]:
    """Return a stable framed-input failure without echoing raw input."""
    if isinstance(exc, json.JSONDecodeError):
        condition = "personal_native_host_framed_json_malformed"
        message = "Native Messaging framed input is not valid JSON."
        detail = f"JSON parsing failed at line {exc.lineno}, column {exc.colno}."
    elif isinstance(exc, UnicodeDecodeError):
        condition = "personal_native_host_framed_json_unreadable"
        message = "Native Messaging framed input could not be decoded as UTF-8."
        detail = "Decode the Native Messaging payload as UTF-8 JSON before sending it."
    elif isinstance(exc, ValueError):
        condition = "personal_native_host_framed_json_not_object"
        message = "Native Messaging framed input must be a JSON object."
        detail = (
            "The framed Native Messaging payload must decode to a JSON object; arrays, "
            "strings, numbers, booleans, and null are not accepted."
        )
    else:
        condition = "personal_native_host_framed_input_invalid"
        message = "Native Messaging framed input could not be processed."
        detail = f"Processing failed with {exc.__class__.__name__}."
    return {
        "ok": False,
        "error": condition,
        "condition": condition,
        "message": message,
        "detail": detail,
        "next_steps": _native_host_framed_input_next_steps(condition),
    }


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
            if not isinstance(message, dict):
                raise ValueError("native host framed payload must be a JSON object")
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            response = native_host_framed_input_failure_response(exc)
        else:
            try:
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
