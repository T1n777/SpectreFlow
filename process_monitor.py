"""
SpectreFlow Dynamic Analysis — Process Monitor
Tracks target process CPU usage with ADAPTIVE BASELINE detection,
detects spikes relative to current system load, and logs child-process creation.

The adaptive approach lets the analyzer work even when a game or other
CPU-heavy application is already running.
"""

import time
import threading
import logging
import statistics

import psutil

import config

logger = logging.getLogger("spectreflow.dynamic.process")


def measure_baseline() -> float:
    """Sample system-wide CPU for a few seconds and return the average.

    This captures the "normal" CPU level BEFORE the target is launched,
    so we can detect only the ADDITIONAL load the target creates.
    """
    samples = []
    interval = config.CPU_BASELINE_WINDOW / config.CPU_BASELINE_SAMPLES

    logger.info(
        "Measuring CPU baseline over %ss (%d samples) ...",
        config.CPU_BASELINE_WINDOW,
        config.CPU_BASELINE_SAMPLES,
    )

    # Prime the first call (always returns 0)
    psutil.cpu_percent(interval=None)

    for _ in range(config.CPU_BASELINE_SAMPLES):
        sample = psutil.cpu_percent(interval=interval)
        samples.append(sample)

    baseline = statistics.mean(samples)
    logger.info(
        "Baseline CPU: %.1f%% (samples: %s)",
        baseline,
        [round(s, 1) for s in samples],
    )
    return baseline


class ProcessMonitor:
    """Monitor a process by PID for CPU spikes and child-process spawning.

    Uses adaptive thresholds:
      1. System-level: flags if system CPU exceeds (baseline + SPIKE_DELTA)
      2. Process-level: flags if the target alone exceeds PROCESS_HARD_LIMIT
    """

    def __init__(self, pid: int, baseline_cpu: float = 0.0):
        self.pid = pid
        self.baseline_cpu = baseline_cpu

        # Adaptive threshold = baseline + delta
        self.spike_threshold = baseline_cpu + config.CPU_SPIKE_DELTA

        self.cpu_spike_detected = False
        self.max_cpu = 0.0            # max system CPU observed
        self.max_process_cpu = 0.0    # max target-process CPU observed
        self.children_spawned: list[str] = []
        self._stop_event = threading.Event()

        logger.info(
            "Adaptive threshold: %.1f%% (baseline %.1f%% + delta %.1f%%)",
            self.spike_threshold,
            baseline_cpu,
            config.CPU_SPIKE_DELTA,
        )

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
                # ── Per-process CPU ──────────────────────────────────
                process_cpu = proc.cpu_percent(interval=config.POLL_INTERVAL)
                if process_cpu > self.max_process_cpu:
                    self.max_process_cpu = process_cpu

                # ── System-wide CPU ─────────────────────────────────
                system_cpu = psutil.cpu_percent(interval=None)
                if system_cpu > self.max_cpu:
                    self.max_cpu = system_cpu

                # ── Check spike conditions ──────────────────────────
                # Condition 1: System CPU jumped above (baseline + delta)
                # This catches malware adding CPU load on top of a game.
                if system_cpu >= self.spike_threshold:
                    if not self.cpu_spike_detected:
                        logger.info(
                            "CPU SPIKE (system): %.1f%% exceeds adaptive "
                            "threshold %.1f%% (baseline was %.1f%%)",
                            system_cpu,
                            self.spike_threshold,
                            self.baseline_cpu,
                        )
                    self.cpu_spike_detected = True

                # Condition 2: Target process alone uses excessive CPU
                # This catches a crypto-miner pinning one core even when
                # overall system CPU looks "normal".
                if process_cpu >= config.CPU_PROCESS_HARD_LIMIT:
                    if not self.cpu_spike_detected:
                        logger.info(
                            "CPU SPIKE (process): target using %.1f%% "
                            "(hard limit %s%%)",
                            process_cpu,
                            config.CPU_PROCESS_HARD_LIMIT,
                        )
                    self.cpu_spike_detected = True

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
            "baseline_cpu_percent": round(self.baseline_cpu, 1),
            "adaptive_threshold": round(self.spike_threshold, 1),
            "max_system_cpu_percent": round(self.max_cpu, 1),
            "max_process_cpu_percent": round(self.max_process_cpu, 1),
            "children_spawned": self.children_spawned,
            "flagged_functions": flagged,
        }
