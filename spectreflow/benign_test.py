"""
A completely benign script — just does some math and prints.
Used to verify SpectreFlow does NOT produce false positives.
"""
import time

total = 0
for i in range(100):
    total += i * i
    time.sleep(0.05)

print(f"Done. Sum of squares: {total}")
