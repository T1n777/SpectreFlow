"""
SpectreFlow Dynamic Analysis — Network Monitor
Polls network connections made by the target process and records remote endpoints.
"""

import time
import threading
import logging

import psutil

import config

logger = logging.getLogger("spectreflow.dynamic.network")


class NetworkMonitor:
    """Monitor outgoing / listening network connections for a given PID."""

    def __init__(self, pid: int):
        self.pid = pid
        self.connections: list[str] = []          # "ip:port" strings
        self._seen: set[tuple] = set()
        self._stop_event = threading.Event()

    # ── public API ───────────────────────────────────────────────────
    def start(self, duration: float | None = None):
        duration = duration or config.MONITOR_DURATION
        deadline = time.time() + duration

        while not self._stop_event.is_set() and time.time() < deadline:
            try:
                proc = psutil.Process(self.pid)
                conns = proc.net_connections(kind="inet")

                for conn in conns:
                    if conn.raddr:
                        endpoint = (conn.raddr.ip, conn.raddr.port)
                        if endpoint not in self._seen:
                            self._seen.add(endpoint)
                            entry = f"{conn.raddr.ip}:{conn.raddr.port}"
                            self.connections.append(entry)
                            logger.info("Network connection: %s", entry)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                # Process ended or we lack permissions — that's fine.
                pass
            except Exception as exc:
                logger.debug("Network poll error: %s", exc)

            time.sleep(config.POLL_INTERVAL)

    def stop(self):
        self._stop_event.set()

    # ── results ──────────────────────────────────────────────────────
    def get_results(self) -> dict:
        flagged = []
        if self.connections:
            flagged.append("network_call")
        return {
            "network_activity": self.connections,
            "flagged_functions": flagged,
        }
