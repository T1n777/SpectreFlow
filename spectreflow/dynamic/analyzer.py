"""
SpectreFlow Dynamic Analysis — Analyzer (Orchestrator)
Launches the target executable, runs all monitors concurrently,
and produces the final analysis result dictionary.
"""

import subprocess
import sys
import time
import threading
import logging

from .process_monitor import ProcessMonitor
from .network_monitor import NetworkMonitor
from .file_monitor import FileMonitor
from . import config

logger = logging.getLogger("spectreflow.dynamic.analyzer")


class DynamicAnalyzer:
    """
    Main entry point for dynamic analysis.

    Usage:
        analyzer = DynamicAnalyzer("path/to/suspicious.exe", duration=30)
        result = analyzer.run()
        print(result)
    """

    def __init__(self, target_path: str, duration: float | None = None):
        self.target_path = target_path
        self.duration = duration or config.MONITOR_DURATION

    # ── public API ───────────────────────────────────────────────────
    def run(self) -> dict:
        """Execute the target and monitor it. Returns the analysis dict."""
        logger.info("=" * 60)
        logger.info("SpectreFlow Dynamic Analysis")
        logger.info("Target : %s", self.target_path)
        logger.info("Duration: %ss", self.duration)
        logger.info("=" * 60)

        # 1. Start file-system monitor BEFORE launching the target
        file_mon = FileMonitor()
        file_mon.start()

        # 2. Launch the target process
        try:
            proc = subprocess.Popen(
                [sys.executable, self.target_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            logger.info("Target launched — PID %d", proc.pid)
        except Exception as exc:
            file_mon.stop()
            logger.error("Failed to launch target: %s", exc)
            return self._empty_result()

        pid = proc.pid

        # 3. Start process & network monitors in threads
        proc_mon = ProcessMonitor(pid)
        net_mon = NetworkMonitor(pid)

        threads = [
            threading.Thread(
                target=proc_mon.start, args=(self.duration,), daemon=True
            ),
            threading.Thread(
                target=net_mon.start, args=(self.duration,), daemon=True
            ),
        ]
        for t in threads:
            t.start()

        # 4. Wait for monitoring duration
        logger.info("Monitoring for %s seconds ...", self.duration)
        time.sleep(self.duration)

        # 5. Tear down
        proc_mon.stop()
        net_mon.stop()
        file_mon.stop()

        for t in threads:
            t.join(timeout=5)

        # Terminate target if still running
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            pass

        # 6. Aggregate results
        return self._aggregate(proc_mon, net_mon, file_mon)

    # ── internals ────────────────────────────────────────────────────
    @staticmethod
    def _aggregate(
        proc_mon: ProcessMonitor,
        net_mon: NetworkMonitor,
        file_mon: FileMonitor,
    ) -> dict:
        proc_res = proc_mon.get_results()
        net_res = net_mon.get_results()
        file_res = file_mon.get_results()

        # Merge flagged functions (deduplicated, ordered)
        all_flagged: list[str] = []
        for src in (proc_res, net_res, file_res):
            for fn in src.get("flagged_functions", []):
                if fn not in all_flagged:
                    all_flagged.append(fn)

        suspicious = bool(
            proc_res["cpu_spike"]
            or net_res["network_activity"]
            or file_res["file_activity"]
            or all_flagged
        )

        return {
            "suspicious": suspicious,
            "network_activity": net_res["network_activity"],
            "file_activity": file_res["file_activity"],
            "cpu_spike": proc_res["cpu_spike"],
            "flagged_functions": all_flagged,
        }

    @staticmethod
    def _empty_result() -> dict:
        return {
            "suspicious": False,
            "network_activity": [],
            "file_activity": [],
            "cpu_spike": False,
            "flagged_functions": [],
        }
