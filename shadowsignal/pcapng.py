"""Minimal PCAPNG reader for packet-header metadata produced by Windows pktmon."""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .models import CapturedFlow, PacketEvent


SECTION_HEADER = b"\x0a\x0d\x0d\x0a"
INTERFACE_DESCRIPTION = 1
ENHANCED_PACKET = 6
LINKTYPE_ETHERNET = 1
LINKTYPE_NULL = 0
LINKTYPE_RAW = 101
LINKTYPE_LOOP = 108
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229


class ProcessLookup(Protocol):
    def lookup(self, local_port: int) -> tuple[str | None, str | None, int | None]: ...


@dataclass(frozen=True)
class _Interface:
    link_type: int
    timestamp_resolution: float = 1e-6


@dataclass(frozen=True)
class _Packet:
    timestamp: float
    transport: str
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    payload_size: int
    server_name: str | None = None


def _tls_server_name(payload: bytes) -> str | None:
    """Extract plaintext SNI from a complete TLS ClientHello record."""
    if (
        len(payload) < 9
        or payload[0] != 0x16
        or payload[1] != 0x03
        or payload[2] > 0x04
    ):
        return None
    record_length = struct.unpack_from("!H", payload, 3)[0]
    record = payload[5 : min(len(payload), 5 + record_length)]
    if len(record) < 4 or record[0] != 0x01:
        return None
    handshake_length = int.from_bytes(record[1:4], "big")
    hello = record[4 : min(len(record), 4 + handshake_length)]
    if len(hello) < 35:
        return None

    offset = 34  # legacy_version + random
    session_id_length = hello[offset]
    offset += 1 + session_id_length
    if offset + 2 > len(hello):
        return None
    cipher_suites_length = struct.unpack_from("!H", hello, offset)[0]
    offset += 2 + cipher_suites_length
    if offset + 1 > len(hello):
        return None
    compression_methods_length = hello[offset]
    offset += 1 + compression_methods_length
    if offset + 2 > len(hello):
        return None
    extensions_length = struct.unpack_from("!H", hello, offset)[0]
    offset += 2
    extensions_end = min(len(hello), offset + extensions_length)

    while offset + 4 <= extensions_end:
        extension_type, extension_length = struct.unpack_from("!HH", hello, offset)
        offset += 4
        extension_end = offset + extension_length
        if extension_end > extensions_end:
            return None
        if extension_type == 0 and extension_length >= 5:
            names_end = offset + 2 + struct.unpack_from("!H", hello, offset)[0]
            cursor = offset + 2
            names_end = min(names_end, extension_end)
            while cursor + 3 <= names_end:
                name_type = hello[cursor]
                name_length = struct.unpack_from("!H", hello, cursor + 1)[0]
                cursor += 3
                if cursor + name_length > names_end:
                    return None
                if name_type == 0:
                    try:
                        hostname = hello[cursor : cursor + name_length].decode("ascii").lower()
                    except UnicodeDecodeError:
                        return None
                    hostname = hostname.rstrip(".")
                    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789-.")
                    if 1 <= len(hostname) <= 253 and set(hostname) <= allowed:
                        return hostname
                    return None
                cursor += name_length
        offset = extension_end
    return None


def _options_timestamp_resolution(body: bytes, endian: str) -> float:
    offset = 8
    while offset + 4 <= len(body):
        code, length = struct.unpack_from(endian + "HH", body, offset)
        offset += 4
        if code == 0:
            break
        value = body[offset : offset + length]
        offset += (length + 3) & ~3
        if code == 9 and value:
            exponent = value[0]
            return 2.0 ** -(exponent & 0x7F) if exponent & 0x80 else 10.0 ** -exponent
    return 1e-6


def _transport_packet(frame: bytes, *, link_type: int, timestamp: float) -> _Packet | None:
    if link_type == LINKTYPE_ETHERNET:
        if len(frame) < 14:
            return None
        network_offset = 14
        ether_type = struct.unpack_from("!H", frame, 12)[0]
        while ether_type in {0x8100, 0x88A8}:
            if len(frame) < network_offset + 4:
                return None
            ether_type = struct.unpack_from("!H", frame, network_offset + 2)[0]
            network_offset += 4
    elif link_type in {LINKTYPE_RAW, LINKTYPE_IPV4, LINKTYPE_IPV6}:
        if not frame:
            return None
        network_offset = 0
        if link_type == LINKTYPE_IPV4:
            ether_type = 0x0800
        elif link_type == LINKTYPE_IPV6:
            ether_type = 0x86DD
        else:
            ether_type = 0x0800 if frame[0] >> 4 == 4 else 0x86DD
    elif link_type in {LINKTYPE_NULL, LINKTYPE_LOOP}:
        if len(frame) < 4:
            return None
        network_offset = 4
        if link_type == LINKTYPE_LOOP:
            families = {struct.unpack_from("!I", frame, 0)[0]}
        else:
            families = {
                struct.unpack_from("<I", frame, 0)[0],
                struct.unpack_from(">I", frame, 0)[0],
            }
        if 2 in families:
            ether_type = 0x0800
        elif families & {10, 24, 28, 30}:
            ether_type = 0x86DD
        else:
            return None
    else:
        return None

    if ether_type == 0x0800:
        if len(frame) < network_offset + 20:
            return None
        version_ihl = frame[network_offset]
        if version_ihl >> 4 != 4:
            return None
        ip_header_size = (version_ihl & 0x0F) * 4
        if ip_header_size < 20 or len(frame) < network_offset + ip_header_size:
            return None
        fragment = struct.unpack_from("!H", frame, network_offset + 6)[0]
        if fragment & 0x1FFF:
            return None
        total_length = struct.unpack_from("!H", frame, network_offset + 2)[0]
        protocol = frame[network_offset + 9]
        source_ip = str(ipaddress.ip_address(frame[network_offset + 12 : network_offset + 16]))
        destination_ip = str(ipaddress.ip_address(frame[network_offset + 16 : network_offset + 20]))
        transport_offset = network_offset + ip_header_size
        ip_payload_size = total_length - ip_header_size
    elif ether_type == 0x86DD:
        if len(frame) < network_offset + 40 or frame[network_offset] >> 4 != 6:
            return None
        ip_payload_size = struct.unpack_from("!H", frame, network_offset + 4)[0]
        protocol = frame[network_offset + 6]
        source_ip = str(ipaddress.ip_address(frame[network_offset + 8 : network_offset + 24]))
        destination_ip = str(ipaddress.ip_address(frame[network_offset + 24 : network_offset + 40]))
        transport_offset = network_offset + 40
    else:
        return None

    if protocol == 6:
        if len(frame) < transport_offset + 20:
            return None
        source_port, destination_port = struct.unpack_from("!HH", frame, transport_offset)
        tcp_header_size = (frame[transport_offset + 12] >> 4) * 4
        if tcp_header_size < 20:
            return None
        payload_size = ip_payload_size - tcp_header_size
        transport = "tcp"
        payload_offset = transport_offset + tcp_header_size
        captured_end = min(len(frame), transport_offset + max(0, ip_payload_size))
        server_name = _tls_server_name(frame[payload_offset:captured_end])
    elif protocol == 17:
        if len(frame) < transport_offset + 8:
            return None
        source_port, destination_port = struct.unpack_from("!HH", frame, transport_offset)
        payload_size = ip_payload_size - 8
        transport = "quic"
        server_name = None
    else:
        return None

    if payload_size <= 0:
        return None
    return _Packet(
        timestamp=timestamp,
        transport=transport,
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=source_port,
        destination_port=destination_port,
        payload_size=payload_size,
        server_name=server_name,
    )


def _read_packets(path: Path) -> list[_Packet]:
    data = path.read_bytes()
    packets: list[_Packet] = []
    interfaces: list[_Interface] = []
    endian: str | None = None
    offset = 0

    while offset + 12 <= len(data):
        raw_type = data[offset : offset + 4]
        if raw_type == SECTION_HEADER:
            byte_order = data[offset + 8 : offset + 12]
            if byte_order == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif byte_order == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                raise ValueError("invalid PCAPNG byte-order magic")
            interfaces = []
        if endian is None:
            raise ValueError("PCAPNG section header is missing")

        block_type, block_length = struct.unpack_from(endian + "II", data, offset)
        if block_length < 12 or block_length % 4 or offset + block_length > len(data):
            raise ValueError("invalid PCAPNG block length")
        if struct.unpack_from(endian + "I", data, offset + block_length - 4)[0] != block_length:
            raise ValueError("mismatched PCAPNG block length")
        body = data[offset + 8 : offset + block_length - 4]

        if block_type == INTERFACE_DESCRIPTION and len(body) >= 8:
            link_type = struct.unpack_from(endian + "H", body, 0)[0]
            interfaces.append(_Interface(link_type, _options_timestamp_resolution(body, endian)))
        elif block_type == ENHANCED_PACKET and len(body) >= 20:
            interface_id, timestamp_high, timestamp_low, captured_length = struct.unpack_from(
                endian + "IIII", body, 0
            )
            if interface_id < len(interfaces) and 20 + captured_length <= len(body):
                raw_timestamp = (timestamp_high << 32) | timestamp_low
                interface = interfaces[interface_id]
                frame = body[20 : 20 + captured_length]
                packet = _transport_packet(
                    frame,
                    link_type=interface.link_type,
                    timestamp=raw_timestamp * interface.timestamp_resolution,
                )
                if packet is not None:
                    packets.append(packet)
        offset += block_length

    return packets


def _packets_to_flows(
    packets: list[_Packet], *, target_ips: set[str], resolver: ProcessLookup
) -> list[CapturedFlow]:
    relevant = [
        packet
        for packet in packets
        if packet.source_ip in target_ips or packet.destination_ip in target_ips
    ]
    if not relevant:
        return []

    started_at = min(packet.timestamp for packet in relevant)
    flows: dict[tuple[str, int, str, int], CapturedFlow] = {}
    seen: set[tuple[float, str, str, int, int, int]] = set()

    for packet in sorted(relevant, key=lambda item: item.timestamp):
        if packet.destination_ip in target_ips and packet.destination_port == 443:
            direction = "out"
            local_port = packet.source_port
            remote_ip = packet.destination_ip
        elif packet.source_ip in target_ips and packet.source_port == 443:
            direction = "in"
            local_port = packet.destination_port
            remote_ip = packet.source_ip
        else:
            continue

        offset_ms = max(0, round((packet.timestamp - started_at) * 1000))
        duplicate_key = (
            round(packet.timestamp, 9),
            packet.source_ip,
            packet.destination_ip,
            packet.source_port,
            packet.destination_port,
            packet.payload_size,
        )
        if duplicate_key in seen:
            continue
        seen.add(duplicate_key)

        key = (packet.transport, local_port, remote_ip, 443)
        flow = flows.get(key)
        if flow is None:
            flow = CapturedFlow(packet.transport, local_port, remote_ip, 443)
            flows[key] = flow
        if packet.server_name and flow.server_name is None:
            flow.server_name = packet.server_name
        flow.events.append(PacketEvent(offset_ms, direction, packet.payload_size))

    for flow in flows.values():
        process_name, parent_process, process_id = resolver.lookup(flow.local_port)
        flow.process_name = process_name
        flow.parent_process = parent_process
        flow.process_id = process_id

    return sorted(flows.values(), key=lambda flow: (flow.inbound_count, len(flow.events)), reverse=True)


def parse_pcapng(
    path: Path,
    *,
    target_ips: set[str],
    resolver: ProcessLookup,
) -> list[CapturedFlow]:
    return _packets_to_flows(_read_packets(path), target_ips=target_ips, resolver=resolver)
