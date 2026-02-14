"""
SpectreFlow Dynamic Analysis — Process Monitor
Tracks target process CPU usage, detects spikes, and logs child-process creation.
"""

import time
import threading
import logging

import psutil

from . import config

logger = logging.getLogger("spectreflow.dynamic.process")


class ProcessMonitor:
    """Monitor a process by PID for CPU spikes and child-process spawning."""

    def __init__(self, pid: int):
        self.pid = pid
        self.cpu_spike_detected = False
        self.max_cpu = 0.0
        self.children_spawned: list[str] = []
        self._stop_event = threading.Event()

    # ── public API ───────────────────────────────────────────────────
    def start(self, duration: float | None = None):
        """Begin monitoring. Blocks for *duration* seconds (or until stop())."""
        duration = duration or config.MONITOR_DURATION
        deadline = time.time() + duration

        try:
            proc = psutil.Process(self.pid)
            # Prime cpu_percent (first call always returns 0)
            proc.cpu_percent(interval=None)
        except psutil.NoSuchProcess:
            logger.warning("PID %d does not exist.", self.pid)
            return

        while not self._stop_event.is_set() and time.time() < deadline:
            try:
                cpu = proc.cpu_percent(interval=config.POLL_INTERVAL)
                if cpu > self.max_cpu:
                    self.max_cpu = cpu
                if cpu >= config.CPU_SPIKE_THRESHOLD:
                    self.cpu_spike_detected = True
                    logger.info(
                        "CPU spike detected: %.1f%% (threshold %s%%)",
                        cpu,
                        config.CPU_SPIKE_THRESHOLD,
                    )

                # Check for child processes
                for child in proc.children(recursive=True):
                    name = child.name()
                    if name not in self.children_spawned:
                        self.children_spawned.append(name)
                        logger.info("Child process spawned: %s", name)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                logger.info("Target process ended or access denied.")
                break

    def stop(self):
        self._stop_event.set()

    # ── results ──────────────────────────────────────────────────────
    def get_results(self) -> dict:
        flagged = []
        if self.children_spawned:
            flagged.append("process_spawn")
        return {
            "cpu_spike": self.cpu_spike_detected,
            "max_cpu_percent": round(self.max_cpu, 1),
            "children_spawned": self.children_spawned,
            "flagged_functions": flagged,
        }
