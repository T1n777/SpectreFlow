"""
TEST 7: Multi-Threat Malware Simulation
Expected: SUSPICIOUS (all flags), HIGH risk
Combines CPU spike, network, files, and processes
"""
import socket
import time
import hashlib
import tempfile
import os
import subprocess
import sys
import threading

print("=== MULTI-THREAT SIMULATION ===")

# Thread 1: CPU intensive operation
def cpu_load():
    print("[CPU] Starting heavy computation...")
    for i in range(500000):
        hashlib.sha256(str(i).encode()).hexdigest()
    print("[CPU] Complete")

# Thread 2: Network activity
def network_activity():
    print("[NET] Attempting connections...")
    for port in [4444, 1337]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.3)
            sock.connect_ex(("127.0.0.1", port))
            sock.close()
        except:
            pass
        time.sleep(0.3)
    print("[NET] Complete")

# Thread 3: File operations
def file_operations():
    print("[FILE] Creating suspicious files...")
    temp_dir = tempfile.gettempdir()
    files = ["malware.exe", "payload.dll", "script.bat"]
    for f in files:
        try:
            path = os.path.join(temp_dir, f)
            with open(path, 'w') as fp:
                fp.write("test")
            time.sleep(0.2)
            os.remove(path)
        except:
            pass
    print("[FILE] Complete")

# Thread 4: Process spawning
def spawn_processes():
    print("[PROC] Spawning children...")
    try:
        if sys.platform == "win32":
            subprocess.Popen(["ping", "-n", "1", "127.0.0.1"],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:
            subprocess.Popen(["ping", "-c", "1", "127.0.0.1"],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except:
        pass
    print("[PROC] Complete")

# Run all threats concurrently
threads = [
    threading.Thread(target=cpu_load),
    threading.Thread(target=network_activity),
    threading.Thread(target=file_operations),
    threading.Thread(target=spawn_processes)
]

for t in threads:
    t.start()

for t in threads:
    t.join()

print("=== SIMULATION COMPLETE ===")
