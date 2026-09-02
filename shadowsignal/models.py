"""Payload-free telemetry models shared by capture and API transport."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


Direction = Literal["in", "out"]


@dataclass(frozen=True)
class PacketEvent:
    offset_ms: int
    direction: Direction
    size: int

    def as_dict(self) -> dict[str, int | str]:
        return {"offset_ms": self.offset_ms, "direction": self.direction, "size": self.size}


@dataclass
class CapturedFlow:
    transport: str
    local_port: int
    remote_ip: str
    remote_port: int
    events: list[PacketEvent] = field(default_factory=list)
    process_name: str | None = None
    parent_process: str | None = None
    process_id: int | None = None

    @property
    def inbound_count(self) -> int:
        return sum(event.direction == "in" for event in self.events)
