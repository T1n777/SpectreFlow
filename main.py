import subprocess
import sys
import os
import json
from spectreflow.graph_visualizer import launch

# Output file for graph data (same as defined in original main.py logic, usually)
OUTPUT_FILE = "r2_output.json"

if __name__ == "__main__":
    # Load analysis results if available
    graph_data = None
    if os.path.exists(OUTPUT_FILE):
        try:
            with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
                graph_data = json.load(f)
            print(f"[*] Loaded graph data from {OUTPUT_FILE}")
        except Exception as e:
            print(f"[!] Failed to load graph data: {e}")

    # Launch GUI with data (or None, which triggers dummy data)
    print("[*] Launching visualizer...")
    launch(data=graph_data)
