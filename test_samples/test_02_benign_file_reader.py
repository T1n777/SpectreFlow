"""
TEST 2: Benign File Reader
Expected: CLEAN verdict, LOW risk
Reads its own source code
"""
import time
import os

print("Reading file...")
with open(__file__, 'r') as f:
    content = f.read()
    lines = content.split('\n')
    
print(f"File has {len(lines)} lines")
time.sleep(2)
print("Done reading")
