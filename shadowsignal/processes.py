"""Best-effort socket-to-process attribution using psutil."""

from __future__ import annotations

import threading
import time

import psutil


class ProcessResolver:
    def __init__(self, target_ips: set[str], interval: float = 0.5):
        self.target_ips = target_ips
        self.interval = interval
        self._cache: dict[int, tuple[str | None, str | None]] = {}
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self.refresh()
        self._thread = threading.Thread(target=self._run, name="shadowsignal-process-resolver", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def lookup(self, local_port: int) -> tuple[str | None, str | None]:
        return self._cache.get(local_port, (None, None))

    def _run(self) -> None:
        while not self._stop.wait(self.interval):
            self.refresh()

    def refresh(self) -> None:
        updated = dict(self._cache)
        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, OSError):
            return
        for connection in connections:
            if not connection.laddr or not connection.raddr or not connection.pid:
                continue
            remote_ip = getattr(connection.raddr, "ip", connection.raddr[0])
            remote_port = getattr(connection.raddr, "port", connection.raddr[1])
            if remote_ip not in self.target_ips or remote_port != 443:
                continue
            local_port = getattr(connection.laddr, "port", connection.laddr[1])
            try:
                process = psutil.Process(connection.pid)
                parent = process.parent()
                updated[local_port] = (process.name(), parent.name() if parent else None)
            except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                continue
        self._cache = updated
