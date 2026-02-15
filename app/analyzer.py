import time
import threading
import logging

from container import get_sandbox, LocalSandbox, DockerSandbox
from process_monitor import ProcessMonitor, measure_baseline
from network_monitor import NetworkMonitor
from file_monitor import FileMonitor
import config

logger = logging.getLogger("spectreflow.dynamic.analyzer")


class DynamicAnalyzer:
    def __init__(self, target_path: str, duration: float = None,
                 docker_image: str = None):
        self.target_path = target_path
        self.duration = duration or config.MONITOR_DURATION
        self.docker_image = docker_image

    def run(self) -> dict:
        sandbox = get_sandbox(self.target_path, docker_image=self.docker_image)

        if isinstance(sandbox, LocalSandbox):
            return self._run_local(sandbox)
        return self._run_docker(sandbox)

    def _run_local(self, sandbox: LocalSandbox) -> dict:
        logger.info("=" * 60)
        logger.info("SpectreFlow Dynamic Analysis (Local Sandbox)")
        logger.info("Target : %s", self.target_path)
        logger.info("Duration: %ss", self.duration)
        logger.info("=" * 60)

        baseline_cpu = measure_baseline()

        sandbox.setup()
        proc = sandbox.launch(self.target_path, duration=self.duration)
        pid = proc.pid

        file_mon = FileMonitor()
        file_mon.start()

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

        sandbox.teardown()

        return self._aggregate(proc_mon, net_mon, file_mon)

    def _run_docker(self, sandbox: DockerSandbox) -> dict:
        logger.info("=" * 60)
        logger.info("SpectreFlow Dynamic Analysis (Docker)")
        logger.info("Target : %s", self.target_path)
        logger.info("Duration: %ss", self.duration)
        logger.info("Image  : %s", sandbox.base_image)
        logger.info("=" * 60)

        sandbox.setup()
        try:
            sandbox.launch(self.target_path, duration=self.duration)
            result = sandbox.get_results()

            logs = sandbox.get_logs()
            if logs:
                for line in logs.strip().splitlines():
                    if not line.strip().startswith("{"):
                        logger.info("[container] %s", line.rstrip())
        finally:
            sandbox.teardown()

        return result

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
