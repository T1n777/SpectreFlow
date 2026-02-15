import time
import threading
import logging

from container import Container
from process_monitor import ProcessMonitor, measure_baseline
from network_monitor import NetworkMonitor
from file_monitor import FileMonitor
import config

logger = logging.getLogger("spectreflow.dynamic.analyzer")


class DynamicAnalyzer:
    def __init__(self, target_path: str, duration: float = None):
        self.target_path = target_path
        self.duration = duration or config.MONITOR_DURATION

    def run(self) -> dict:
        logger.info("=" * 60)
        logger.info("SpectreFlow Dynamic Analysis")
        logger.info("Target : %s", self.target_path)
        logger.info("Duration: %ss", self.duration)
        logger.info("=" * 60)

        baseline_cpu = measure_baseline()

        container = Container(self.target_path, timeout=self.duration)
        container.setup()

        file_mon = FileMonitor()
        file_mon.start()

        proc = container.launch()
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

        container.teardown()

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
            or net_res.get("suspicious_connections")
            or file_res.get("suspicious_file_write")
            or file_res.get("sensitive_dir_write")
            or all_flagged
        )

        return {
            "suspicious": suspicious,
            "target_location": proc_res.get("target_location"),
            "network_activity": net_res["network_activity"],
            "suspicious_connections": net_res.get("suspicious_connections", []),
            "file_activity": file_res["file_activity"],
            "suspicious_file_write": file_res.get("suspicious_file_write", False),
            "sensitive_dir_write": file_res.get("sensitive_dir_write", False),
            "cpu_spike": proc_res["cpu_spike"],
            "flagged_functions": all_flagged,
        }

