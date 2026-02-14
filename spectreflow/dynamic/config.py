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


# ── CPU Spike Detection ─────────────────────────────────────────────
# CPU usage percentage above which a "spike" is flagged.
CPU_SPIKE_THRESHOLD = 80.0


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
