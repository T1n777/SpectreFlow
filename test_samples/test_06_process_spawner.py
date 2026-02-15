"""
TEST 6: Process Spawner
Expected: SUSPICIOUS (process spawn), MEDIUM risk
Creates child processes
"""
import subprocess
import time
import sys

print("Spawning child processes...")

# Spawn harmless child processes
processes = []
for i in range(3):
    try:
        # Spawn a simple process (ping with count 1)
        if sys.platform == "win32":
            proc = subprocess.Popen(
                ["ping", "-n", "1", "127.0.0.1"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
        else:
            proc = subprocess.Popen(
                ["ping", "-c", "1", "127.0.0.1"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
        processes.append(proc)
        print(f"Spawned process {i+1}")
        time.sleep(0.5)
    except Exception as e:
        print(f"Failed to spawn process: {e}")

# Wait for completion
for proc in processes:
    proc.wait()

print("All processes completed")
