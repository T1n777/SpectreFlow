"""
TEST 4: Network Scanner
Expected: SUSPICIOUS (network activity), HIGH risk
Attempts to connect to suspicious ports
"""
import socket
import time

print("Starting network scan...")

# Try to connect to suspicious ports
suspicious_ports = [4444, 5555, 1337, 31337]
target = "127.0.0.1"

for port in suspicious_ports:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((target, port))
        print(f"Port {port}: {'Open' if result == 0 else 'Closed'}")
        sock.close()
    except Exception as e:
        print(f"Port {port}: Error")
    time.sleep(0.5)

print("Scan complete")
