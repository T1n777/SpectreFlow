<div align="center">

---
<pre>
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║    ██████╗ ██████╗ ███████╗ ██████╗████████╗██████╗ ███████╗   ║
║   ██╔════╝ ██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔══██╗██╔════╝   ║
║   ╚█████╗  ██████╔╝█████╗  ██║        ██║   ██████╔╝█████╗     ║
║    ╚═══██╗ ██╔═══╝ ██╔══╝  ██║        ██║   ██╔══██╗██╔══╝     ║
║   ██████╔╝ ██║     ███████╗╚██████╗   ██║   ██║  ██║███████╗   ║
║   ╚═════╝  ╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝   ║
║               F L O W  -  Malware Analysis Suite               ║
╚════════════════════════════════════════════════════════════════╝
</pre>
---

</div>

SpectreFlow is a dynamic and static malware analysis engine for Windows. It monitors CPU, network, and file-system activity in real time, computes a composite risk score, and presents the results in a polished dark-themed GUI dashboard with rounded-corner cards, themed scrollbars, and an interactive control-flow graph visualiser.

## Key Features

- 🔬 **Dynamic Analysis** — Real-time monitoring of CPU spikes, outbound network connections, file-system events, and child-process spawning.
- 📊 **Static Analysis** — (Optional) Control-flow graph extraction and complexity metrics via `radare2` / `r2pipe`.
- ⚠️ **Risk Scoring** — Composite 0–32 risk score classified as LOW / MEDIUM / HIGH.
- 🗺️ **Graph Visualiser** — Interactive networkx + matplotlib viewer with hierarchical layout and colour-coded nodes.

## Installation

1. **Clone the repository:**
    ```bash
    git clone <repository_url>
    cd SpectreFlow/spectreflow
    ```

2. **Install dependencies** (virtual environment recommended):
    ```bash
    pip install -r ../requirements.txt
    ```

> **Note:** `r2pipe` is only needed for static analysis (`--static` flag). It requires [radare2](https://github.com/radareorg/radare2) to be installed and on your `PATH`.

## Usage

### Quick start (welcome window)

Simply run without arguments — the welcome window will open and let you pick a file:

```bash
python main.py
```

### CLI with a target path

```bash
python main.py path/to/target.exe
```

### Command-Line Arguments

| Argument               | Description                                                                             |
| :--------------------- | :-------------------------------------------------------------------------------------- |
| `target`               | Path to target script / executable. **Optional** — opens the welcome window if omitted. |
| `--duration <seconds>` | Monitoring duration (default: **15 s**).                                                |
| `--output <file>`      | Save JSON report to file.                                                               |
| `--static`             | Run static analysis via r2pipe (requires radare2).                                      |
| `--visualize`          | Open the graph visualiser after analysis.                                               |
| `--no-gui`             | Terminal-only output (no dashboard).                                                    |
| `--verbose`, `-v`      | Enable debug logging.                                                                   |

### Examples

```bash
# 30-second analysis, save report
python main.py target.exe --duration 30 --output report.json

# Static analysis + graph visualiser
python main.py target.exe --static --visualize

# Headless mode with verbose logging
python main.py target.exe --no-gui --verbose
```

## Project Structure

| File                  | Purpose                                                           |
| :-------------------- | :---------------------------------------------------------------- |
| `main.py`             | Entry point — welcome window, CLI parsing, orchestration          |
| `report_gui.py`       | Analysis dashboard GUI (log viewer, result cards, action buttons) |
| `graph_visualizer.py` | Interactive control-flow graph viewer                             |
| `analyzer.py`         | Dynamic analysis orchestrator                                     |
| `process_monitor.py`  | CPU usage & child-process tracking                                |
| `network_monitor.py`  | Outbound network connection monitoring                            |
| `file_monitor.py`     | File-system event watcher (via watchdog)                          |
| `static_analysis.py`  | radare2-based CFG extraction & metrics                            |
| `risk_engine.py`      | Composite risk scoring & threat classification                    |
| `config.py`           | Global thresholds, watched directories, suspicious patterns       |
| `run_analysis.py`     | Headless dynamic-analysis CLI (no GUI, no static)                 |
| `benign_test.py`      | Benign sample script for false-positive testing                   |

## Requirements

- **Python 3.10+** (uses `X | Y` union type syntax)
- **Windows 10 / 11** (for full process & network monitoring, dark title bar)
- **radare2** (optional — only for `--static`)
- **All modules in requirements.txt** (installing dependencies)

