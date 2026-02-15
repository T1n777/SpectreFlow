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

SpectreFlow is a comprehensive malware analysis tool that combines **static analysis**, **dynamic monitoring**, and **threat intelligence** to detect malicious behavior in executable files and scripts.

## 🚀 Key Features

### 🔍 Static Analysis
- **PE Analysis**: Detects suspicious imports, high entropy sections (packed code), and digital signature verification.
- **Control Flow Graph (CFG)**: visualizes the execution flow using **Radare2**.
- **YARA Scanning**: Integrated YARA rules for detecting known threats (ransomware, keyloggers, anti-debug).
- **String Analysis**: Extracts suspicious strings (URLs, IPs, shell commands).

### ⚡ Dynamic Analysis
- **Process Monitoring**: Tracks CPU spikes, child process spawning, and shell invocations.
- **Network Monitoring**: Detects connections to suspicious ports or non-benign hosts.
- **File System Monitoring**: Watches for suspicious file modifications (e.g., ransomware encryption patterns) and writes to sensitive directories.
- **Sandboxing**:
  - **Docker Sandbox** (Linux targets): Runs analysis in an isolated container.
  - **Local Sandbox** (Windows targets): Executes with safety constraints and watchdog timers.

### 🛡 Threat Intelligence
- **VirusTotal Integration**: Checks file hashes against the VirusTotal database (API key required).
- **MalwareBazaar**: Cross-references file hashes with known malware samples.

### 📊 Visualization & Reporting
- **GUI Dashboard**: Real-time analysis logs, risk scoring, and interactive charts.
- **Graph Visualizer**: Visual representation of the control flow graph.
- **JSON Reports**: Exportable detailed verification reports.

---

## 🛠 Installation

### Prerequisites
- **Python 3.10+**
- **[Radare2](https://rada.re/n/radare2.html)** (Required for static analysis features)
- **Docker** (Optional, for Linux containerized analysis)

### Setup
1. Clone the repository:
   ```bash
   git clone https://github.com/T1n777/spectreflow.git
   cd spectreflow
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. (Optional) Configure API Keys:
   - Open `config.py`
   - Add your VirusTotal API key:
     ```python
     VIRUSTOTAL_API_KEY = "your_api_key_here"
     ```

---

## 🎮 Usage

### GUI Mode (Default)
Simply run the main script to launch the welcome screen:
```bash
python main.py
```
- Select a file to analyze.
- View real-time logs and the final verdict.
- Click **"View Graph"** to see the Control Flow Graph.

### CLI Mode
Run analysis directly from the terminal:
```bash
python main.py path/to/malware.exe --no-gui
```

### Options
| Argument          | Description                                    |
| :---------------- | :--------------------------------------------- |
| `target`          | Path to the file to analyze                    |
| `--duration`      | Analysis duration in seconds (default: 15s)    |
| `--static`        | Enable deep static analysis (requires Radare2) |
| `--visualize`     | Launch the graph visualizer after analysis     |
| `--no-gui`        | Run in headless mode (terminal output only)    |
| `--output <file>` | Save the analysis report to a JSON file        |
| `--verbose`, `-v` | Enable debug logging                           |

---

## 📂 Project Structure

- **`main.py`**: Entry point for the application.
- **`analyzer.py`**: Orchestrates dynamic analysis (process, network, file).
- **`static_analysis.py`**: Handles Radare2 integration for CFG and metrics.
- **`pe_analysis.py`**: Parses PE headers and sections using `pefile`.
- **`risk_engine.py`**: Calculates risk scores based on aggregated findings.
- **`verdict_engine.py`**: Generates human-readable verdicts (CLEAN, SUSPICIOUS, MALICIOUS).
- **`report_gui.py`**: Tkinter-based dashboard for results.
- **`graph_visualizer.py`**: Matplotlib/NetworkX graph visualization.
- **`container.py`**: Manages Docker and local sandboxes.

