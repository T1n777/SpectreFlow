#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
import sys
import threading
import time

import psutil

POLL_INTERVAL = 0.5
CPU_SPIKE_DELTA = 25.0
CPU_HARD_LIMIT = 85.0
SPIKE_MIN_COUNT = 3
SUSPICIOUS_EXT = {".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs",
                  ".scr", ".pif", ".msi", ".jar", ".hta"}
SUSPICIOUS_PORTS = {4444, 5555, 1337, 31337, 9090, 6666, 6667, 3389, 5900}
BENIGN_PORTS = {80, 443, 53, 123, 993, 587, 25, 110, 143}
BENIGN_HOSTS = {"127.0.0.1", "::1", "0.0.0.0", "localhost"}


class ProcessMonitorAgent:
    def __init__(self, pid, baseline, duration):
        self.pid = pid
        self.baseline = baseline
        self.threshold = baseline + CPU_SPIKE_DELTA
        self.duration = duration
        self.cpu_spike = False
        self.max_cpu = 0.0
        self.max_proc_cpu = 0.0
        self.children = []
        self._children_seen = set()
        self._consec = 0

    def run(self):
        deadline = time.time() + self.duration
        try:
            proc = psutil.Process(self.pid)
            proc.cpu_percent(interval=None)
        except psutil.NoSuchProcess:
            return
        while time.time() < deadline:
            try:
                pcpu = proc.cpu_percent(interval=POLL_INTERVAL)
                scpu = psutil.cpu_percent(interval=None)
                self.max_proc_cpu = max(self.max_proc_cpu, pcpu)
                self.max_cpu = max(self.max_cpu, scpu)
                if not self.cpu_spike:
                    if scpu >= self.threshold or pcpu >= CPU_HARD_LIMIT:
                        self._consec += 1
                        if self._consec >= SPIKE_MIN_COUNT:
                            self.cpu_spike = True
                    else:
                        self._consec = 0
                for child in proc.children(recursive=True):
                    n = child.name()
                    if n not in self._children_seen:
                        self._children_seen.add(n)
                        self.children.append(n)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                break

    def results(self):
        return {
            "cpu_spike": self.cpu_spike,
            "max_system_cpu": round(self.max_cpu, 1),
            "max_process_cpu": round(self.max_proc_cpu, 1),
            "children_spawned": self.children,
            "flagged_functions": ["process_spawn"] if self.children else [],
        }


class NetworkMonitorAgent:
    def __init__(self, pid, duration):
        self.pid = pid
        self.duration = duration
        self.connections = []
        self.suspicious = []
        self._seen = set()

    def _classify(self, ip, port):
        if ip in BENIGN_HOSTS:
            return False
        if port in SUSPICIOUS_PORTS:
            return True
        if port not in BENIGN_PORTS:
            return True
        return False

    def run(self):
        deadline = time.time() + self.duration
        try:
            proc = psutil.Process(self.pid)
        except psutil.NoSuchProcess:
            return
        while time.time() < deadline:
            try:
                for p in [proc] + proc.children(recursive=True):
                    try:
                        for c in p.net_connections(kind="inet"):
                            if c.raddr:
                                ep = (c.raddr.ip, c.raddr.port)
                                if ep not in self._seen:
                                    self._seen.add(ep)
                                    entry = f"{c.raddr.ip}:{c.raddr.port}"
                                    self.connections.append(entry)
                                    if self._classify(c.raddr.ip, c.raddr.port):
                                        self.suspicious.append(entry)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                break
            time.sleep(POLL_INTERVAL)

    def results(self):
        return {
            "network_activity": self.connections,
            "suspicious_connections": self.suspicious,
            "flagged_functions": ["network_call"] if self.suspicious else [],
        }


class FileMonitorAgent:
    def __init__(self, watch_dirs, duration):
        self.watch_dirs = watch_dirs
        self.duration = duration
        self.events = []
        self._snapshots = {}
        self.has_suspicious_ext = False

    def _snapshot(self):
        snap = {}
        for d in self.watch_dirs:
            if not os.path.isdir(d):
                continue
            try:
                for f in os.listdir(d):
                    full = os.path.join(d, f)
                    if os.path.isfile(full):
                        snap[full] = os.path.getmtime(full)
            except OSError:
                pass
        return snap

    def run(self):
        before = self._snapshot()
        time.sleep(self.duration)
        after = self._snapshot()

        for path in after:
            basename = os.path.basename(path)
            if path not in before:
                self.events.append({"action": "created", "file": basename})
                self._check_ext(basename)
            elif after[path] != before[path]:
                self.events.append({"action": "modified", "file": basename})
                self._check_ext(basename)

        for path in before:
            if path not in after:
                basename = os.path.basename(path)
                self.events.append({"action": "deleted", "file": basename})

    def _check_ext(self, basename):
        _, ext = os.path.splitext(basename)
        if ext.lower() in SUSPICIOUS_EXT:
            self.has_suspicious_ext = True

    def results(self):
        return {
            "file_activity": self.events,
            "suspicious_file_write": self.has_suspicious_ext,
            "flagged_functions": ["file_write"] if self.has_suspicious_ext else [],
        }


def measure_baseline():
    psutil.cpu_percent(interval=None)
    samples = [psutil.cpu_percent(interval=0.5) for _ in range(6)]
    return sum(samples) / len(samples)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target")
    parser.add_argument("--duration", type=float, default=15)
    args = parser.parse_args()

    baseline = measure_baseline()

    target = os.path.abspath(args.target)
    _, ext = os.path.splitext(target)
    if ext.lower() in (".py", ".pyw"):
        cmd = [sys.executable, target]
    else:
        cmd = [target]

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    pid = proc.pid

    watch_dirs = ["/tmp", os.path.dirname(target)]

    proc_mon = ProcessMonitorAgent(pid, baseline, args.duration)
    net_mon = NetworkMonitorAgent(pid, args.duration)
    file_mon = FileMonitorAgent(watch_dirs, args.duration)

    threads = [
        threading.Thread(target=proc_mon.run, daemon=True),
        threading.Thread(target=net_mon.run, daemon=True),
        threading.Thread(target=file_mon.run, daemon=True),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=args.duration + 5)

    try:
        proc.kill()
        proc.wait(timeout=5)
    except Exception:
        pass

    pr = proc_mon.results()
    nr = net_mon.results()
    fr = file_mon.results()

    seen = set()
    flagged = []
    for src in (pr, nr, fr):
        for fn in src.get("flagged_functions", []):
            if fn not in seen:
                seen.add(fn)
                flagged.append(fn)

    suspicious = bool(
        pr["cpu_spike"]
        or nr.get("suspicious_connections")
        or fr.get("suspicious_file_write")
        or flagged
    )

    result = {
        "suspicious": suspicious,
        "target_location": target,
        "network_activity": nr["network_activity"],
        "suspicious_connections": nr["suspicious_connections"],
        "file_activity": fr["file_activity"],
        "suspicious_file_write": fr["suspicious_file_write"],
        "sensitive_dir_write": False,
        "cpu_spike": pr["cpu_spike"],
        "flagged_functions": flagged,
    }

    print(json.dumps(result))


if __name__ == "__main__":
    main()
