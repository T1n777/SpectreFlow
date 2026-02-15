import time

total = 0
for i in range(100):
    total += i * i
    time.sleep(0.05)

print(f"Done. Sum of squares: {total}")
