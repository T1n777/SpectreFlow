"""
TEST 10: Ransomware Simulation
Expected: SUSPICIOUS (all indicators), CRITICAL/HIGH risk
Simulates file encryption, network callback, CPU spike
"""
import os
import time
import socket
import tempfile
import hashlib
import threading

print("[RANSOMWARE SIM] Starting...")

def encrypt_files():
    """Simulate file encryption"""
    print("[CRYPT] Encrypting files...")
    temp_dir = tempfile.gettempdir()
    
    # Create and "encrypt" files
    for i in range(5):
        filename = f"document{i}.txt.encrypted"
        filepath = os.path.join(temp_dir, filename)
        try:
            with open(filepath, 'w') as f:
                # Simulate encryption with hash
                encrypted = hashlib.sha256(f"data{i}".encode()).hexdigest()
                f.write(encrypted)
            time.sleep(0.3)
        except:
            pass
    
    # Cleanup
    for i in range(5):
        try:
            os.remove(os.path.join(temp_dir, f"document{i}.txt.encrypted"))
        except:
            pass
    print("[CRYPT] Complete")

def command_and_control():
    """Simulate C2 beacon"""
    print("[C2] Calling home...")
    c2_servers = [
        ("127.0.0.1", 4444),
        ("127.0.0.1", 1337)
    ]
    
    for server, port in c2_servers:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            sock.connect_ex((server, port))
            sock.close()
            time.sleep(0.5)
        except:
            pass
    print("[C2] Complete")

def crypto_operations():
    """Heavy crypto operations"""
    print("[CRYPTO] Processing...")
    for i in range(100000):
        hashlib.sha256(str(i).encode()).hexdigest()
    print("[CRYPTO] Complete")

# Execute all malicious operations
threads = [
    threading.Thread(target=encrypt_files),
    threading.Thread(target=command_and_control),
    threading.Thread(target=crypto_operations)
]

for t in threads:
    t.start()

for t in threads:
    t.join()

print("[RANSOMWARE SIM] Complete")
