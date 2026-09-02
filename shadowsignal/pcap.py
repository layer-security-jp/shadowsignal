"""Minimal classic PCAP reader for captures produced by macOS tcpdump."""

from __future__ import annotations

import struct
from pathlib import Path

from .models import CapturedFlow
from .pcapng import ProcessLookup, _Packet, _packets_to_flows, _transport_packet


_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e-6),
    b"\xa1\xb2\xc3\xd4": (">", 1e-6),
    b"\x4d\x3c\xb2\xa1": ("<", 1e-9),
    b"\xa1\xb2\x3c\x4d": (">", 1e-9),
}


def _read_packets(path: Path) -> list[_Packet]:
    data = path.read_bytes()
    if len(data) < 24 or data[:4] not in _MAGIC:
        raise ValueError("invalid classic PCAP header")
    endian, fractional_resolution = _MAGIC[data[:4]]
    _major, _minor, _zone, _sigfigs, _snaplen, link_type = struct.unpack_from(
        endian + "HHiIII", data, 4
    )

    packets: list[_Packet] = []
    offset = 24
    while offset < len(data):
        if offset + 16 > len(data):
            break
        seconds, fraction, captured_length, _original_length = struct.unpack_from(
            endian + "IIII", data, offset
        )
        offset += 16
        if offset + captured_length > len(data):
            break
        frame = data[offset : offset + captured_length]
        offset += captured_length
        packet = _transport_packet(
            frame,
            link_type=link_type,
            timestamp=seconds + fraction * fractional_resolution,
        )
        if packet is not None:
            packets.append(packet)
    return packets


def parse_pcap(
    path: Path,
    *,
    target_ips: set[str],
    resolver: ProcessLookup,
) -> list[CapturedFlow]:
    return _packets_to_flows(_read_packets(path), target_ips=target_ips, resolver=resolver)


def parse_pcaps(
    paths: list[Path],
    *,
    target_ips: set[str],
    resolver: ProcessLookup,
) -> list[CapturedFlow]:
    packets = []
    for path in paths:
        packets.extend(_read_packets(path))
    return _packets_to_flows(packets, target_ips=target_ips, resolver=resolver)
