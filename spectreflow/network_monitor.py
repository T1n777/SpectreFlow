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

        # Create the Process handle ONCE — avoids a kernel lookup every iteration
        try:
            proc = psutil.Process(self.pid)
        except psutil.NoSuchProcess:
            return

        # Cache references to avoid repeated attribute lookups in the hot loop
        seen_add = self._seen.add
        seen = self._seen
        connections_append = self.connections.append
        poll_interval = config.POLL_INTERVAL
        stop_is_set = self._stop_event.is_set

        while not stop_is_set() and time.time() < deadline:
            try:
                for conn in proc.net_connections(kind="inet"):
                    raddr = conn.raddr
                    if raddr:
                        endpoint = (raddr.ip, raddr.port)
                        if endpoint not in seen:
                            seen_add(endpoint)
                            entry = f"{raddr.ip}:{raddr.port}"
                            connections_append(entry)
                            logger.info("Network connection: %s", entry)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                break
            except Exception as exc:
                logger.debug("Network poll error: %s", exc)

            time.sleep(poll_interval)

    def stop(self):
        self._stop_event.set()

    # ── results ──────────────────────────────────────────────────────
    def get_results(self) -> dict:
        return {
            "network_activity": self.connections,
            "flagged_functions": ["network_call"] if self.connections else [],
        }
