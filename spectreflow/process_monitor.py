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
    interval = config.CPU_BASELINE_WINDOW / config.CPU_BASELINE_SAMPLES
    n_samples = config.CPU_BASELINE_SAMPLES

    logger.info(
        "Measuring CPU baseline over %ss (%d samples) ...",
        config.CPU_BASELINE_WINDOW,
        n_samples,
    )

    # Prime the first call (always returns 0)
    psutil.cpu_percent(interval=None)

    # Use a pre-allocated list for slightly less overhead
    samples = [psutil.cpu_percent(interval=interval) for _ in range(n_samples)]

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
        self._children_seen: set[str] = set()  # O(1) dedup for child names
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

        # Cache values outside the hot loop
        poll_interval = config.POLL_INTERVAL
        spike_threshold = self.spike_threshold
        hard_limit = config.CPU_PROCESS_HARD_LIMIT
        baseline = self.baseline_cpu
        stop_is_set = self._stop_event.is_set
        children_seen = self._children_seen

        while not stop_is_set() and time.time() < deadline:
            try:
                # ── Per-process CPU ──────────────────────────────────
                process_cpu = proc.cpu_percent(interval=poll_interval)
                if process_cpu > self.max_process_cpu:
                    self.max_process_cpu = process_cpu

                # ── System-wide CPU ─────────────────────────────────
                system_cpu = psutil.cpu_percent(interval=None)
                if system_cpu > self.max_cpu:
                    self.max_cpu = system_cpu

                # ── Check spike conditions ──────────────────────────
                if not self.cpu_spike_detected:
                    if system_cpu >= spike_threshold:
                        logger.info(
                            "CPU SPIKE (system): %.1f%% exceeds adaptive "
                            "threshold %.1f%% (baseline was %.1f%%)",
                            system_cpu, spike_threshold, baseline,
                        )
                        self.cpu_spike_detected = True
                    elif process_cpu >= hard_limit:
                        logger.info(
                            "CPU SPIKE (process): target using %.1f%% "
                            "(hard limit %s%%)",
                            process_cpu, hard_limit,
                        )
                        self.cpu_spike_detected = True

                # ── Child processes (O(1) dedup via set) ─────────────
                for child in proc.children(recursive=True):
                    name = child.name()
                    if name not in children_seen:
                        children_seen.add(name)
                        self.children_spawned.append(name)
                        logger.info("Child process spawned: %s", name)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                logger.info("Target process ended or access denied.")
                break

    def stop(self):
        self._stop_event.set()

    # ── results ──────────────────────────────────────────────────────
    def get_results(self) -> dict:
        return {
            "cpu_spike": self.cpu_spike_detected,
            "baseline_cpu_percent": round(self.baseline_cpu, 1),
            "adaptive_threshold": round(self.spike_threshold, 1),
            "max_system_cpu_percent": round(self.max_cpu, 1),
            "max_process_cpu_percent": round(self.max_process_cpu, 1),
            "children_spawned": self.children_spawned,
            "flagged_functions": ["process_spawn"] if self.children_spawned else [],
        }
