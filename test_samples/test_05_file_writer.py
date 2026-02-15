"""
TEST 5: File Writer (Suspicious Extensions)
Expected: SUSPICIOUS (file activity), MEDIUM-HIGH risk
Creates files with suspicious extensions
"""
import os
import tempfile
import time

print("Creating files...")
temp_dir = tempfile.gettempdir()

# Create files with suspicious extensions
suspicious_files = [
    "temp_script.bat",
    "temp_script.ps1",
    "temp_config.dll"
]

for filename in suspicious_files:
    filepath = os.path.join(temp_dir, filename)
    try:
        with open(filepath, 'w') as f:
            f.write("# Temporary test file")
        print(f"Created: {filename}")
        time.sleep(0.5)
    except Exception as e:
        print(f"Failed to create {filename}: {e}")

print("File creation complete")

# Cleanup
time.sleep(1)
for filename in suspicious_files:
    filepath = os.path.join(temp_dir, filename)
    try:
        if os.path.exists(filepath):
            os.remove(filepath)
    except:
        pass
