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

_SCRIPT_EXTENSIONS = {".py", ".pyw"}


class DynamicAnalyzer:
    def __init__(self, target_path: str, duration: float | None = None):
        self.target_path = target_path
        self.duration = duration or config.MONITOR_DURATION

    def _build_command(self) -> list[str]:
        _, ext = os.path.splitext(self.target_path)
        if ext.lower() in _SCRIPT_EXTENSIONS:
            return [sys.executable, self.target_path]
        return [self.target_path]

    def run(self) -> dict:
        cmd = self._build_command()
        is_binary = len(cmd) == 1

        logger.info("=" * 60)
        logger.info("SpectreFlow Dynamic Analysis")
        logger.info("Target : %s", self.target_path)
        logger.info("Type   : %s", "binary" if is_binary else "script")
        logger.info("Duration: %ss", self.duration)
        logger.info("=" * 60)

        baseline_cpu = measure_baseline()

        file_mon = FileMonitor()
        file_mon.start()

        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            logger.info("Target launched — PID %d", proc.pid)
        except Exception as exc:
            file_mon.stop()
            logger.error("Failed to launch target: %s", exc)
            return self._empty_result()

        pid = proc.pid
        proc_mon = ProcessMonitor(pid, baseline_cpu=baseline_cpu)
        net_mon = NetworkMonitor(pid)

        threads = [
            threading.Thread(target=proc_mon.start, args=(self.duration,), daemon=True),
            threading.Thread(target=net_mon.start, args=(self.duration,), daemon=True),
        ]
        for t in threads:
            t.start()

        logger.info("Monitoring for %s seconds ...", self.duration)
        time.sleep(self.duration)

        proc_mon.stop()
        net_mon.stop()
        file_mon.stop()

        for t in threads:
            t.join(timeout=5)

        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            pass

        return self._aggregate(proc_mon, net_mon, file_mon)

    @staticmethod
    def _aggregate(proc_mon, net_mon, file_mon) -> dict:
        proc_res = proc_mon.get_results()
        net_res = net_mon.get_results()
        file_res = file_mon.get_results()

        seen: set[str] = set()
        all_flagged: list[str] = []
        for src in (proc_res, net_res, file_res):
            for fn in src.get("flagged_functions", []):
                if fn not in seen:
                    seen.add(fn)
                    all_flagged.append(fn)

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
