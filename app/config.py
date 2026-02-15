import os
import tempfile

VIRUSTOTAL_API_KEY = "1d2ae72afdf9042e5e17e68dfebbf1d2470c3042cb2e3d89a94e488fe3c14b05"

MONITOR_DURATION     = 30
CONTAINER_TIMEOUT    = 30
DOCKER_IMAGE         = "python:3.11-slim"
POLL_INTERVAL        = 0.5

CPU_BASELINE_WINDOW  = 3
CPU_BASELINE_SAMPLES = 6
CPU_SPIKE_DELTA      = 25.0
CPU_PROCESS_HARD_LIMIT = 85.0
CPU_SPIKE_MIN_COUNT  = 3

if os.name == "nt":
    WATCHED_DIRS = [
        tempfile.gettempdir(),
        os.path.join(os.path.expanduser("~"), "Downloads"),
        os.path.join(os.path.expanduser("~"), "Desktop"),
    ]
else:
    WATCHED_DIRS = [
        tempfile.gettempdir(),
        os.path.join(os.path.expanduser("~"), "Downloads"),
        "/tmp",
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

SUSPICIOUS_PORTS = {4444, 5555, 1337, 31337, 9090, 6666, 6667, 3389, 5900}
BENIGN_PORTS     = {80, 443, 53, 123, 993, 587, 25, 110, 143}
BENIGN_HOSTS     = {"127.0.0.1", "::1", "0.0.0.0", "localhost"}

if os.name == "nt":
    SENSITIVE_DIRS = {
        os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "System32"),
        os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "SysWOW64"),
        os.path.join(os.path.expanduser("~"), "AppData", "Roaming", "Microsoft",
                     "Windows", "Start Menu", "Programs", "Startup"),
    }
else:
    SENSITIVE_DIRS = {
        "/etc",
        "/usr/bin",
        "/usr/sbin",
    }
