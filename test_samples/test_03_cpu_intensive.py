"""
TEST 3: CPU Intensive (Benign Purpose)
Expected: SUSPICIOUS (CPU spike), MEDIUM risk
Simulates legitimate heavy computation
"""
import time
import hashlib

print("Starting computation...")
for i in range(1000000):
    # Simulate heavy computation
    result = hashlib.sha256(str(i).encode()).hexdigest()
    if i % 100000 == 0:
        print(f"Progress: {i}")

print("Computation complete")
