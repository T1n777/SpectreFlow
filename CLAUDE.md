# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SpectreFlow is a malware analysis suite combining **dynamic behavioral monitoring**, **static binary analysis**, and **threat intelligence** lookups to classify executables and scripts as CLEAN, LIKELY SAFE, SUSPICIOUS, or MALICIOUS. Built with Python 3.10+, it features both a Tkinter GUI dashboard and a headless CLI mode.

## Setup & Commands

### Install dependencies
```bash
pip install -r requirements.txt
```

### External tools
- **Radare2** — required for static analysis / CFG extraction (`--static` flag)
- **Docker** — optional, for Linux containerized sandbox analysis (falls back to local sandbox)
- **yara-python** — optional, commented out in requirements.txt; enables YARA rule scanning

### Run (GUI mode)
```bash
cd app
python main.py
```

### Run (CLI / headless mode)
```bash
cd app
python main.py path/to/file.exe --no-gui
```

### Run (minimal headless, dynamic analysis only)
```bash
cd app
python run_analysis.py path/to/file.exe
```

### CLI flags
- `--duration <seconds>` — analysis duration (default 15s)
- `--static` — enable Radare2-based CFG analysis
- `--visualize` — launch graph visualizer after analysis
- `--output <file>` — save JSON report
- `--verbose` / `-v` — debug logging

### Test with benign sample
```bash
cd app
python main.py benign_test.py --no-gui
```

## Architecture

All source lives in `app/`. There is no test framework — `benign_test.py` is a sample benign file used as analysis input, not a unit test.

### Analysis Pipeline (executed in order)

1. **Sandbox execution** (`container.py`) — `LocalSandbox` (Windows/.exe) or `DockerSandbox` (Python scripts on Linux). Docker uses `sandbox_agent.py` as the in-container entry point.
2. **Dynamic monitoring** — three monitors run in parallel threads during sandbox execution:
   - `process_monitor.py` — CPU spike detection (3+ consecutive readings above baseline+25% or >85%)
   - `network_monitor.py` — classifies connections as suspicious vs benign by port/host
   - `file_monitor.py` — watches temp/Downloads/Desktop for suspicious file writes using watchdog
3. **Static analysis** (`static_analysis.py`) — Radare2 CFG extraction and complexity metrics (optional)
4. **PE analysis** (`pe_analysis.py`) — section entropy, packer detection, dangerous API imports, entry point anomalies, string scanning (max 10MB)
5. **Threat intelligence**:
   - `hash_lookup.py` — MalwareBazaar API lookup
   - `vt_lookup.py` — VirusTotal API v3 (requires API key in `config.py`)
   - `yara_scanner.py` — 7 built-in YARA rules (UPX, shell invocation, ransomware, keylogger, anti-debug, process injection)
6. **Scoring** (`risk_engine.py`) — weighted 0-55 scale across 7 signal categories
7. **Verdict** (`verdict_engine.py`) — maps score + signals to verdict with confidence percentage

### Entry Points

- `main.py` — primary entry: GUI welcome screen (file picker) or CLI with `--no-gui`
- `run_analysis.py` — minimal headless entry: dynamic analysis only, no static/intel/GUI
- `report_gui.py` — launched by `main.py` for real-time dashboard with log streaming
- `graph_visualizer.py` — CFG or dynamic-result graph visualization (matplotlib + networkx)

### Key Design Patterns

- **Graceful degradation**: missing optional deps (docker, yara, radare2, network APIs) return empty results instead of crashing
- **Platform-aware**: Windows paths (System32, AppData/Startup) and Linux paths (/etc, /usr/bin) handled via `config.py`
- **Logging**: namespaced loggers (`spectreflow.<module>`), GUI uses `QueueHandler` to bridge log records to Tkinter text widget
- **Sandbox fallback**: Docker unavailable → automatic fallback to LocalSandbox with watchdog timer

### Configuration (`config.py`)

Central location for all thresholds and constants: monitor duration, CPU spike delta (25%), suspicious ports/extensions, watched directories, sensitive directories, and the VirusTotal API key.

### Risk Scoring Weights (out of 55 total)

| Category | Max Points |
|---|---|
| Dynamic signals | 10 |
| Static/CFG metrics | 5 |
| PE analysis findings | 10 |
| Hash lookup (known malware) | 10 |
| Suspicious strings | 5 |
| YARA matches | 5 |
| VirusTotal detections | 10 |

Classification: HIGH RISK >= 25, MEDIUM >= 12, LOW < 12
