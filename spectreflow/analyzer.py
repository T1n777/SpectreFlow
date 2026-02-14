"""
SpectreFlow Dynamic Analysis — Analyzer (Orchestrator)
Launches the target executable, runs all monitors concurrently,
and produces the final analysis result dictionary.
"""

import os
import subprocess
import sys
import time
import threading
import logging

from process_monitor import ProcessMonitor, measure_baseline
from network_monitor import NetworkMonitor
from file_monitor import FileMonitor
import config

logger = logging.getLogger("spectreflow.dynamic.analyzer")

# File extensions that are treated as Python scripts (run via interpreter).
_SCRIPT_EXTENSIONS = {".py", ".pyw"}


class DynamicAnalyzer:
    """
    Main entry point for dynamic analysis.

    Supports both Python scripts (.py) and compiled binaries (.exe, ELF, etc.).

    Usage:
        analyzer = DynamicAnalyzer("path/to/suspicious.exe", duration=30)
        result = analyzer.run()
        print(result)
    """

    def __init__(self, target_path: str, duration: float | None = None):
        self.target_path = target_path
        self.duration = duration or config.MONITOR_DURATION

    # ── helpers ──────────────────────────────────────────────────────
    def _build_command(self) -> list[str]:
        """Return the command list to launch the target.

        * .py / .pyw  → run via the Python interpreter
        * everything else (.exe, ELF, etc.) → run directly as a binary
        """
        _, ext = os.path.splitext(self.target_path)
        if ext.lower() in _SCRIPT_EXTENSIONS:
            return [sys.executable, self.target_path]
        else:
            return [self.target_path]

    # ── public API ───────────────────────────────────────────────────
    def run(self) -> dict:
        """Execute the target and monitor it. Returns the analysis dict."""
        cmd = self._build_command()
        is_binary = len(cmd) == 1

        logger.info("=" * 60)
        logger.info("SpectreFlow Dynamic Analysis")
        logger.info("Target : %s", self.target_path)
        logger.info("Type   : %s", "binary" if is_binary else "script")
        logger.info("Duration: %ss", self.duration)
        logger.info("=" * 60)

        # 1. Measure CPU baseline BEFORE doing anything else.
        #    This learns the current system load (e.g. a game running).
        baseline_cpu = measure_baseline()

        # 2. Start file-system monitor BEFORE launching the target
        file_mon = FileMonitor()
        file_mon.start()

        # 3. Launch the target process
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            logger.info("Target launched — PID %d", proc.pid)
        except Exception as exc:
            file_mon.stop()
            logger.error("Failed to launch target: %s", exc)
            return self._empty_result()

        pid = proc.pid

        # 4. Start process & network monitors in threads
        proc_mon = ProcessMonitor(pid, baseline_cpu=baseline_cpu)
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

        # 5. Wait for monitoring duration
        logger.info("Monitoring for %s seconds ...", self.duration)
        time.sleep(self.duration)

        # 6. Tear down
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

        # 7. Aggregate results
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

        # Merge flagged functions — O(n) via set instead of O(n²) via list scan
        seen: set[str] = set()
        all_flagged: list[str] = []
        for src in (proc_res, net_res, file_res):
            for fn in src.get("flagged_functions", []):
                if fn not in seen:
                    seen.add(fn)
                    all_flagged.append(fn)

        # Suspicious = actual malicious indicators, NOT raw file activity.
        # Background OS .tmp files are recorded but don't trigger the flag.
        suspicious = bool(
            proc_res["cpu_spike"]
            or net_res["network_activity"]
            or all_flagged
        )

        return {
            "suspicious": suspicious,
            "target_location": proc_res.get("target_location"),
            "network_activity": net_res["network_activity"],
            "file_activity": file_res["file_activity"],
            "cpu_spike": proc_res["cpu_spike"],
            "flagged_functions": all_flagged,
        }

    @staticmethod
    def _empty_result() -> dict:
        return {
            "suspicious": False,
            "target_location": None,
            "network_activity": [],
            "file_activity": [],
            "cpu_spike": False,
            "flagged_functions": [],
        }

