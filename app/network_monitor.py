import time
import threading
import logging

import psutil
import config

logger = logging.getLogger("spectreflow.dynamic.network")


class NetworkMonitor:

    def __init__(self, pid: int):
        self.pid = pid
        self.connections: list[str] = []
        self.suspicious_connections: list[str] = []
        self._seen: set[tuple] = set()
        self._stop = threading.Event()

    def _classify(self, ip: str, port: int) -> bool:
        if ip in config.BENIGN_HOSTS:
            return False
        if port in config.SUSPICIOUS_PORTS:
            return True
        if port not in config.BENIGN_PORTS:
            return True
        return False

    def start(self, duration: float | None = None):
        duration = duration or config.MONITOR_DURATION
        deadline = time.time() + duration

        try:
            proc = psutil.Process(self.pid)
        except psutil.NoSuchProcess:
            return

        while not self._stop.is_set() and time.time() < deadline:
            try:
                for p in [proc] + proc.children(recursive=True):
                    try:
                        for conn in p.net_connections(kind="inet"):
                            if conn.raddr:
                                endpoint = (conn.raddr.ip, conn.raddr.port)
                                if endpoint not in self._seen:
                                    self._seen.add(endpoint)
                                    entry = f"{conn.raddr.ip}:{conn.raddr.port}"
                                    self.connections.append(entry)
                                    if self._classify(conn.raddr.ip, conn.raddr.port):
                                        self.suspicious_connections.append(entry)
                                        logger.info("Suspicious connection: %s", entry)
                                    else:
                                        logger.info("Benign connection: %s", entry)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                break
            except Exception as exc:
                logger.debug("Network poll error: %s", exc)

            time.sleep(config.POLL_INTERVAL)

    def stop(self):
        self._stop.set()

    def get_results(self) -> dict:
        return {
            "network_activity": self.connections,
            "suspicious_connections": self.suspicious_connections,
            "flagged_functions": ["network_call"] if self.suspicious_connections else [],
        }
