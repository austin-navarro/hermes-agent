"""Strict opt-in output contract for no-agent cron multipart delivery."""

from __future__ import annotations

import json
from typing import Any

MULTIPART_OUTPUT_FORMAT = "multipart-v1"
MULTIPART_ENVELOPE_VERSION = "hermes-no-agent-multipart/v1"
MAX_MULTIPART_MESSAGES = 10
MAX_MULTIPART_PART_CHARS = 4000
MAX_MULTIPART_PART_BYTES = 4000
MAX_MULTIPART_TOTAL_BYTES = 20_000


class MultipartOutputError(ValueError):
    """The opted-in script output is not a valid multipart-v1 envelope."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise MultipartOutputError(f"duplicate envelope key: {key}")
        result[key] = value
    return result


def parse_multipart_v1(stdout: str) -> tuple[str, ...]:
    """Validate and return exact ordered message bodies from multipart-v1 JSON."""
    try:
        envelope = json.loads(stdout, object_pairs_hook=_reject_duplicate_keys)
    except MultipartOutputError:
        raise
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        raise MultipartOutputError(f"invalid multipart-v1 JSON: {exc}") from exc

    if not isinstance(envelope, dict) or set(envelope) != {"version", "messages"}:
        raise MultipartOutputError("envelope must contain exactly 'version' and 'messages'")
    if envelope["version"] != MULTIPART_ENVELOPE_VERSION:
        raise MultipartOutputError(
            f"version must be exactly {MULTIPART_ENVELOPE_VERSION!r}")
    messages = envelope["messages"]
    if not isinstance(messages, list):
        raise MultipartOutputError("messages must be an array")
    if not 1 <= len(messages) <= MAX_MULTIPART_MESSAGES:
        raise MultipartOutputError(
            f"messages must contain 1..{MAX_MULTIPART_MESSAGES} parts")

    total_bytes = 0
    for index, body in enumerate(messages):
        if not isinstance(body, str):
            raise MultipartOutputError(f"messages[{index}] must be text")
        if not body.strip():
            raise MultipartOutputError(f"messages[{index}] must not be empty or whitespace-only")
        encoded_size = len(body.encode("utf-8"))
        if len(body) > MAX_MULTIPART_PART_CHARS or encoded_size > MAX_MULTIPART_PART_BYTES:
            raise MultipartOutputError(
                f"messages[{index}] exceeds {MAX_MULTIPART_PART_CHARS} characters or "
                f"{MAX_MULTIPART_PART_BYTES} UTF-8 bytes")
        total_bytes += encoded_size
    if total_bytes > MAX_MULTIPART_TOTAL_BYTES:
        raise MultipartOutputError(
            f"message bodies exceed {MAX_MULTIPART_TOTAL_BYTES} total UTF-8 bytes")
    return tuple(messages)
