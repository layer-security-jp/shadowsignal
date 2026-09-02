"""Target-scoped Windows pktmon and macOS tcpdump capture backends."""

from __future__ import annotations

import ctypes
import ipaddress
import os
import platform
import re
import signal
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path

from .models import CapturedFlow
from .pcap import parse_pcaps
from .pcapng import parse_pcapng
from .processes import ProcessResolver


MAX_TARGET_IPS = 30
PKTMON_SNAPSHOT_BYTES = 512
TCPDUMP_SNAPSHOT_BYTES = 512
MAX_CAPTURE_BYTES = 32 * 1024 * 1024


class CaptureError(RuntimeError):
    """A safe, user-facing capture failure."""


def resolve_target(hostname: str) -> set[str]:
    addresses = {
        item[4][0]
        for item in socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
    }
    if not addresses:
        raise CaptureError(f"No IP addresses resolved for {hostname}")
    if len(addresses) > MAX_TARGET_IPS:
        raise CaptureError(
            f"{hostname} resolved to {len(addresses)} addresses; the safe limit is {MAX_TARGET_IPS}"
        )
    return addresses


def _is_administrator() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def _run_pktmon(executable: str, *arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        [executable, *arguments],
        capture_output=True,
        text=True,
        errors="replace",
        check=False,
    )
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout or "unknown pktmon error").strip()[-800:]
        raise CaptureError(f"pktmon {' '.join(arguments[:2])} failed: {detail}")
    return result


def _has_active_filters(output: str) -> bool:
    """Detect numbered filter rows without relying on the Windows display language."""
    return any(re.match(r"^\s*\d+\s+\S+", line) for line in output.splitlines())


def _add_target_filters(executable: str, target_ips: set[str]) -> None:
    for index, address in enumerate(sorted(target_ips), start=1):
        _run_pktmon(
            executable,
            "filter",
            "add",
            f"ShadowSignal-{index:02d}",
            "--ip-address",
            address,
            "--port",
            "443",
        )


def _capture_windows(
    *,
    target_host: str,
    duration: int,
) -> list[CapturedFlow]:
    if not _is_administrator():
        raise PermissionError

    executable = shutil.which("pktmon.exe") or shutil.which("pktmon")
    if not executable:
        raise CaptureError("pktmon.exe was not found; Windows 10/11 is required")

    target_ips = resolve_target(target_host)
    existing_filters = _run_pktmon(executable, "filter", "list").stdout
    if _has_active_filters(existing_filters):
        raise CaptureError(
            "pktmon already has active filters; remove them after confirming they are not in use, then retry"
        )

    resolver = ProcessResolver(target_ips)
    filters_added = False
    capture_started = False

    with tempfile.TemporaryDirectory(prefix="shadowsignal-pktmon-") as temporary_directory:
        capture_etl = Path(temporary_directory) / "capture.etl"
        capture_pcapng = Path(temporary_directory) / "capture.pcapng"
        try:
            filters_added = True
            _add_target_filters(executable, target_ips)
            resolver.start()
            _run_pktmon(
                executable,
                "start",
                "--capture",
                "--comp",
                "nics",
                "--pkt-size",
                str(PKTMON_SNAPSHOT_BYTES),
                "--file-name",
                str(capture_etl),
                "--file-size",
                "32",
            )
            capture_started = True
            time.sleep(duration)
        finally:
            if capture_started:
                _run_pktmon(executable, "stop", check=False)
            resolver.stop()
            if filters_added:
                _run_pktmon(executable, "filter", "remove", check=False)

        if not capture_etl.exists():
            raise CaptureError("pktmon completed without producing a capture file")
        _run_pktmon(
            executable,
            "etl2pcap",
            str(capture_etl),
            "--out",
            str(capture_pcapng),
        )
        if not capture_pcapng.exists():
            raise CaptureError("pktmon did not produce the temporary pcapng file")
        try:
            return parse_pcapng(capture_pcapng, target_ips=target_ips, resolver=resolver)
        except (OSError, ValueError) as exc:
            raise CaptureError(f"could not parse pktmon output: {exc}") from exc


def _tcpdump_filter(target_ips: set[str]) -> str:
    hosts = " or ".join(f"host {address}" for address in sorted(target_ips))
    return f"({hosts}) and port 443"


def _route_interface(address: str) -> str:
    executable = shutil.which("route") or "/sbin/route"
    arguments = [executable, "-n", "get"]
    if ipaddress.ip_address(address).version == 6:
        arguments.append("-inet6")
    arguments.append(address)
    result = subprocess.run(
        arguments,
        capture_output=True,
        text=True,
        errors="replace",
        check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "route lookup failed").strip()[-800:]
        raise CaptureError(f"could not determine the macOS route for {address}: {detail}")
    match = re.search(r"^\s*interface:\s*([A-Za-z0-9._-]+)\s*$", result.stdout, re.MULTILINE)
    if not match:
        raise CaptureError(f"macOS route lookup did not return an interface for {address}")
    return match.group(1)


def _target_interfaces(target_ips: set[str]) -> dict[str, set[str]]:
    interfaces: dict[str, set[str]] = {}
    failures: list[str] = []
    for address in sorted(target_ips):
        try:
            interface = _route_interface(address)
        except CaptureError as exc:
            failures.append(str(exc))
            continue
        interfaces.setdefault(interface, set()).add(address)
    if not interfaces:
        detail = "; ".join(failures)[-1_600:]
        raise CaptureError(f"none of the resolved target addresses has a usable macOS route: {detail}")
    return interfaces


def _stop_tcpdump(process: subprocess.Popen[str]) -> tuple[str, bool]:
    """Stop a capture and report whether the termination was initiated here.

    On macOS a filtered tcpdump can remain blocked in a packet read after
    SIGINT/SIGTERM when no more matching traffic arrives.  The capture uses
    packet-buffered output (``-U``), so escalating to SIGKILL is safe once the
    normal shutdown windows have elapsed.  A process that had already exited
    is still treated as an unexpected capture failure by the caller.
    """
    controlled_stop = process.poll() is None
    if controlled_stop:
        process.send_signal(signal.SIGINT)
    try:
        _stdout, stderr = process.communicate(timeout=1)
    except subprocess.TimeoutExpired:
        process.kill()
        try:
            _stdout, stderr = process.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            _stdout, stderr = process.communicate()
    return stderr or "", controlled_stop


def _capture_macos(
    *,
    target_host: str,
    duration: int,
) -> list[CapturedFlow]:
    if os.geteuid() != 0:
        raise PermissionError

    executable = shutil.which("tcpdump")
    if not executable:
        built_in_tcpdump = Path("/usr/sbin/tcpdump")
        if not built_in_tcpdump.is_file():
            raise CaptureError("the built-in macOS tcpdump executable was not found")
        executable = str(built_in_tcpdump)

    target_ips = resolve_target(target_host)
    resolver = ProcessResolver(target_ips)

    with tempfile.TemporaryDirectory(prefix="shadowsignal-tcpdump-") as temporary_directory:
        interfaces = _target_interfaces(target_ips)
        captures: list[Path] = []
        processes: list[subprocess.Popen[str]] = []
        diagnostics: list[tuple[str, bool]] = []
        resolver.start()
        try:
            for index, (interface, addresses) in enumerate(sorted(interfaces.items()), start=1):
                capture_pcap = Path(temporary_directory) / f"capture-{index:02d}.pcap"
                command = [
                    executable,
                    "-i",
                    interface,
                    "-p",
                    "-s",
                    str(TCPDUMP_SNAPSHOT_BYTES),
                    "-U",
                    "-w",
                    str(capture_pcap),
                    _tcpdump_filter(addresses),
                ]
                try:
                    process = subprocess.Popen(
                        command,
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.PIPE,
                        text=True,
                        errors="replace",
                    )
                except OSError as exc:
                    raise CaptureError(f"could not start tcpdump on {interface}: {exc}") from exc
                captures.append(capture_pcap)
                processes.append(process)

            time.sleep(0.35)
            for process in processes:
                if process.poll() is not None:
                    detail = _stop_tcpdump(process).strip()[-800:] or "tcpdump exited before capture started"
                    raise CaptureError(f"tcpdump failed: {detail}")

            deadline = time.monotonic() + duration
            while time.monotonic() < deadline:
                if any(process.poll() is not None for process in processes):
                    break
                total_size = sum(path.stat().st_size for path in captures if path.exists())
                if total_size >= MAX_CAPTURE_BYTES:
                    break
                time.sleep(min(0.25, max(0, deadline - time.monotonic())))
        finally:
            diagnostics.extend(_stop_tcpdump(process) for process in processes)
            resolver.stop()

        for process, (diagnostic, controlled_stop) in zip(processes, diagnostics):
            if process.returncode not in {0, -signal.SIGINT} and not controlled_stop:
                detail = diagnostic.strip()[-800:] or f"tcpdump exited with status {process.returncode}"
                raise CaptureError(f"tcpdump failed: {detail}")
        if not captures or any(not path.exists() or path.stat().st_size < 24 for path in captures):
            detail = "\n".join(item[0] for item in diagnostics).strip()[-800:]
            raise CaptureError(
                "tcpdump completed without producing a capture file"
                + (f": {detail}" if detail else "")
            )
        try:
            return parse_pcaps(captures, target_ips=target_ips, resolver=resolver)
        except (OSError, ValueError) as exc:
            raise CaptureError(f"could not parse tcpdump output: {exc}") from exc


def capture_flows(
    *,
    target_host: str,
    duration: int,
) -> list[CapturedFlow]:
    system = platform.system()
    if system == "Windows":
        return _capture_windows(target_host=target_host, duration=duration)
    if system == "Darwin":
        return _capture_macos(target_host=target_host, duration=duration)
    raise CaptureError("live capture supports Windows 10/11 and macOS 13 or newer")
