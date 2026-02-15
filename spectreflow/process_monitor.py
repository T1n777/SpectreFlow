import os
import time
import threading
import logging
import statistics

import psutil
import config

logger = logging.getLogger("spectreflow.dynamic.process")


def measure_baseline() -> float:
    interval = config.CPU_BASELINE_WINDOW / config.CPU_BASELINE_SAMPLES
    logger.info(
        "Measuring CPU baseline over %ss (%d samples) ...",
        config.CPU_BASELINE_WINDOW, config.CPU_BASELINE_SAMPLES,
    )
    psutil.cpu_percent(interval=None)
    samples = [psutil.cpu_percent(interval=interval)
               for _ in range(config.CPU_BASELINE_SAMPLES)]
    baseline = statistics.mean(samples)
    logger.info("Baseline CPU: %.1f%% (samples: %s)",
                baseline, [round(s, 1) for s in samples])
    return baseline


class ProcessMonitor:

    def __init__(self, pid: int, baseline_cpu: float = 0.0):
        self.pid = pid
        self.baseline_cpu = baseline_cpu
        self.spike_threshold = baseline_cpu + config.CPU_SPIKE_DELTA
        self.cpu_spike_detected = False
        self.max_cpu = 0.0
        self.max_process_cpu = 0.0
        self.children_spawned: list[str] = []
        self._children_seen: set[str] = set()
        self._stop = threading.Event()
        self.target_location: str | None = None

        logger.info(
            "Adaptive threshold: %.1f%% (baseline %.1f%% + delta %.1f%%)",
            self.spike_threshold, baseline_cpu, config.CPU_SPIKE_DELTA,
        )

    def start(self, duration: float | None = None):
        duration = duration or config.MONITOR_DURATION
        deadline = time.time() + duration

        try:
            proc = psutil.Process(self.pid)
            proc.cpu_percent(interval=None)
            self._discover_location(proc)
        except psutil.NoSuchProcess:
            logger.warning("PID %d does not exist.", self.pid)
            return

        while not self._stop.is_set() and time.time() < deadline:
            try:
                process_cpu = proc.cpu_percent(interval=config.POLL_INTERVAL)
                self.max_process_cpu = max(self.max_process_cpu, process_cpu)

                system_cpu = psutil.cpu_percent(interval=None)
                self.max_cpu = max(self.max_cpu, system_cpu)

                if not self.cpu_spike_detected:
                    if system_cpu >= self.spike_threshold:
                        logger.info(
                            "CPU SPIKE (system): %.1f%% exceeds adaptive "
                            "threshold %.1f%% (baseline was %.1f%%)",
                            system_cpu, self.spike_threshold, self.baseline_cpu,
                        )
                        self.cpu_spike_detected = True
                    elif process_cpu >= config.CPU_PROCESS_HARD_LIMIT:
                        logger.info(
                            "CPU SPIKE (process): target using %.1f%% "
                            "(hard limit %s%%)",
                            process_cpu, config.CPU_PROCESS_HARD_LIMIT,
                        )
                        self.cpu_spike_detected = True

                for child in proc.children(recursive=True):
                    name = child.name()
                    if name not in self._children_seen:
                        self._children_seen.add(name)
                        self.children_spawned.append(name)
                        logger.info("Child process spawned: %s", name)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                logger.info("Target process ended or access denied.")
                break

    def stop(self):
        self._stop.set()

    def _discover_location(self, proc: psutil.Process):
        try:
            cmdline = proc.cmdline()
            exe_path = proc.exe()
            for arg in cmdline[1:]:
                if arg.endswith((".py", ".pyw")):
                    resolved = os.path.abspath(arg)
                    if os.path.isfile(resolved):
                        self.target_location = resolved
                        logger.info("Target location: %s", resolved)
                        return
            if exe_path and os.path.isfile(exe_path):
                self.target_location = os.path.abspath(exe_path)
                logger.info("Target location: %s", self.target_location)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    def get_results(self) -> dict:
        return {
            "cpu_spike":              self.cpu_spike_detected,
            "baseline_cpu_percent":   round(self.baseline_cpu, 1),
            "adaptive_threshold":     round(self.spike_threshold, 1),
            "max_system_cpu_percent": round(self.max_cpu, 1),
            "max_process_cpu_percent": round(self.max_process_cpu, 1),
            "children_spawned":       self.children_spawned,
            "target_location":        self.target_location,
            "flagged_functions":      ["process_spawn"] if self.children_spawned else [],
        }
