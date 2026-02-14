import os
import tempfile

MONITOR_DURATION = 30
POLL_INTERVAL = 0.5

CPU_BASELINE_WINDOW = 3
CPU_BASELINE_SAMPLES = 6
CPU_SPIKE_DELTA = 15.0
CPU_PROCESS_HARD_LIMIT = 70.0

WATCHED_DIRS = [
    tempfile.gettempdir(),
    os.path.join(os.path.expanduser("~"), "Downloads"),
    os.path.join(os.path.expanduser("~"), "Desktop"),
]

SUSPICIOUS_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs",
    ".scr", ".pif", ".msi", ".jar", ".hta",
}

FLAGGED_FUNCTIONS = [
    "network_call", "file_write", "process_spawn",
    "registry_modify", "privilege_escalate",
    "keylog", "screen_capture", "dll_inject",
]

SUSPICIOUS_PORTS = {4444, 5555, 1337, 31337, 8080, 9090}
