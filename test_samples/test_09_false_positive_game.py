"""
TEST 9: Legitimate Game Simulation
Expected: Possible FALSE POSITIVE - HIGH CPU is normal for games
Should ideally be CLEAN due to adaptive baseline
"""
import time
import hashlib

print("Game starting...")
print("Loading assets...")

# Games legitimately use high CPU
for frame in range(300):
    # Simulate game loop
    for _ in range(100):
        hashlib.sha256(str(frame).encode()).hexdigest()
    
    if frame % 50 == 0:
        print(f"Frame {frame}/300")
    
    time.sleep(0.01)

print("Game finished")
