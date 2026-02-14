"""
SpectreFlow Dynamic Analysis — Configuration
Central configuration for all monitoring thresholds and parameters.
"""

import os
import tempfile


# ── Monitoring Duration ──────────────────────────────────────────────
# How long (in seconds) to monitor the target process.
MONITOR_DURATION = 30

# Polling interval (in seconds) for process & network monitors.
POLL_INTERVAL = 0.5


# ── CPU Spike Detection (Adaptive Baseline) ─────────────────────────
# How many seconds to sample system CPU *before* launching the target,
# in order to learn the current baseline (e.g. a game already running).
CPU_BASELINE_WINDOW = 3

# Number of samples taken during the baseline window.
CPU_BASELINE_SAMPLES = 6

# A spike is flagged when system CPU rises more than this many
# percentage-points ABOVE the measured baseline.
# Example: baseline = 65% (game running) → spike threshold = 65 + 15 = 80%.
#          baseline = 10% (idle)         → spike threshold = 10 + 15 = 25%.
CPU_SPIKE_DELTA = 15.0

# Hard upper-limit: if the target *process alone* uses more than this
# percentage on any single core, it is flagged regardless of baseline.
# (Catches crypto-miners pinning a core even when system average is low.)
CPU_PROCESS_HARD_LIMIT = 70.0



# ── File System Monitoring ───────────────────────────────────────────
# Directories to watch for file-system activity.
WATCHED_DIRS = [
    tempfile.gettempdir(),                          # system temp
    os.path.join(os.path.expanduser("~"), "Downloads"),
    os.path.join(os.path.expanduser("~"), "Desktop"),
]


# ── Suspicious Indicators ───────────────────────────────────────────
# File extensions considered suspicious when created / modified.
SUSPICIOUS_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs",
    ".scr", ".pif", ".msi", ".jar", ".hta",
}

# Function / API names that are flagged when detected in behavior.
FLAGGED_FUNCTIONS = [
    "network_call",
    "file_write",
    "process_spawn",
    "registry_modify",
    "privilege_escalate",
    "keylog",
    "screen_capture",
    "dll_inject",
]


# ── Network Monitoring ──────────────────────────────────────────────
# Ports commonly associated with malicious activity.
SUSPICIOUS_PORTS = {4444, 5555, 1337, 31337, 8080, 9090}
