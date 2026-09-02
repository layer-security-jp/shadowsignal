"""Build the strictly allowlisted shape-only API payload."""

from __future__ import annotations

import uuid

from .models import CapturedFlow, PacketEvent


SCHEMA_VERSION = "shadowsignal-shape/v1"
MAX_EVENTS = 512
MAX_WINDOW_MS = 120_000
TIME_QUANTUM_MS = 10
SIZE_QUANTUM_BYTES = 32
MAX_SIZE_BYTES = 1_536


def _quantize_time(offset_ms: int) -> int:
    return ((offset_ms + TIME_QUANTUM_MS // 2) // TIME_QUANTUM_MS) * TIME_QUANTUM_MS


def _quantize_size(size: int) -> int:
    rounded_up = ((max(1, size) + SIZE_QUANTUM_BYTES - 1) // SIZE_QUANTUM_BYTES) * SIZE_QUANTUM_BYTES
    return min(MAX_SIZE_BYTES, rounded_up)


def build_shape_payload(flow: CapturedFlow, *, observation_id: str | None = None) -> dict:
    ordered = sorted(flow.events, key=lambda event: event.offset_ms)
    if not ordered:
        raise ValueError("at least one packet event is required")
    started_at = ordered[0].offset_ms
    selected = [event for event in ordered if event.offset_ms - started_at <= MAX_WINDOW_MS]
    if len(selected) > MAX_EVENTS:
        last = len(selected) - 1
        indexes = [round(index * last / (MAX_EVENTS - 1)) for index in range(MAX_EVENTS)]
        selected = [selected[index] for index in indexes]
    return {
        "schema_version": SCHEMA_VERSION,
        "observation_id": observation_id or "obs_" + uuid.uuid4().hex,
        "transport": "quic" if flow.transport == "quic" else "tcp",
        "granularity": "l4_segment",
        "events": [
            {
                "offset_ms": _quantize_time(event.offset_ms - started_at),
                "direction": event.direction,
                "size": _quantize_size(event.size),
            }
            for event in selected
        ],
    }


def build_session_payload(
    flows: list[CapturedFlow], *, observation_id: str | None = None
) -> dict:
    """Build one destination-scoped observation across concurrent TLS flows."""
    events = sorted(
        (event for flow in flows for event in flow.events),
        key=lambda event: event.offset_ms,
    )
    if not events:
        raise ValueError("at least one packet event is required")
    transports = {flow.transport for flow in flows if flow.events}
    session = CapturedFlow("quic" if transports == {"quic"} else "tcp", 0, "", 443)
    session.events = [PacketEvent(event.offset_ms, event.direction, event.size) for event in events]
    return build_shape_payload(session, observation_id=observation_id)
