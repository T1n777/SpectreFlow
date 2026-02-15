"""
TEST 1: Benign Calculator
Expected: CLEAN verdict, LOW risk
"""
import time

print("Starting calculator...")
result = 0
for i in range(100):
    result += i * i
    time.sleep(0.02)

print(f"Calculation complete: {result}")
