import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import logging
import json
import queue

BG       = "#1e1e2e"
BG_DARK  = "#181825"
BG_CARD  = "#313244"
FG       = "#cdd6f4"
FG_DIM   = "#a6adc8"
ACCENT   = "#89b4fa"
GREEN    = "#a6e3a1"
RED      = "#f38ba8"
ORANGE   = "#fab387"
YELLOW   = "#f9e2af"
BORDER   = "#45475a"

THREAT_COLORS = {"HIGH": RED, "MEDIUM": ORANGE, "LOW": GREEN}
FONT      = ("Segoe UI", 10)
FONT_BOLD = ("Segoe UI", 10, "bold")
FONT_SM   = ("Segoe UI", 9)
FONT_LG   = ("Segoe UI", 14, "bold")
FONT_XL   = ("Segoe UI", 22, "bold")
MONO      = ("Consolas", 9)


class QueueHandler(logging.Handler):
    def __init__(self, log_queue):
        super().__init__()
        self.log_queue = log_queue

    def emit(self, record):
        self.log_queue.put(self.format(record))


class AnalysisApp:
    def __init__(self, root: tk.Tk, target: str, duration: float,
                 run_static: bool, run_visualize: bool, verbose: bool):
        self.root = root
        self.target = target
        self.duration = duration
        self.run_static = run_static
        self.run_visualize = run_visualize
        self.verbose = verbose

        self.log_queue = queue.Queue()
        self.result = None
        self.risk_score = 0
        self.threat_level = "—"

        self.root.title("SpectreFlow — Analysis Dashboard")
        self.root.configure(bg=BG)
        self.root.state("zoomed")
        self.root.minsize(1000, 700)

        self._setup_logging()
        self._build_ui()
        self._start_analysis()

    def _setup_logging(self):
        level = logging.DEBUG if self.verbose else logging.INFO
        handler = QueueHandler(self.log_queue)
        handler.setFormatter(logging.Formatter(
            "%(asctime)s │ %(name)-30s │ %(message)s", datefmt="%H:%M:%S"
        ))
        root_logger = logging.getLogger()
        root_logger.setLevel(level)
        root_logger.addHandler(handler)

    def _build_ui(self):
        header = tk.Frame(self.root, bg=BG_DARK, height=60)
        header.pack(fill=tk.X)
        header.pack_propagate(False)

        tk.Label(
            header, text="⬡ SpectreFlow", font=FONT_LG, fg=ACCENT, bg=BG_DARK,
        ).pack(side=tk.LEFT, padx=16, pady=10)

        self.status_label = tk.Label(
            header, text="⏳ Analyzing...", font=FONT_BOLD, fg=YELLOW, bg=BG_DARK
        )
        self.status_label.pack(side=tk.LEFT, padx=20)

        self.risk_badge = tk.Label(
            header, text="", font=FONT_LG, fg=BG, bg=BG_DARK
        )
        self.risk_badge.pack(side=tk.RIGHT, padx=16, pady=10)

        body = tk.Frame(self.root, bg=BG)
        body.pack(fill=tk.BOTH, expand=True, padx=16, pady=(8, 16))
        body.columnconfigure(0, weight=3, minsize=420)
        body.columnconfigure(1, weight=2, minsize=300)
        body.rowconfigure(0, weight=1)

        left = tk.Frame(body, bg=BG)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        left.rowconfigure(1, weight=1)

        tk.Label(left, text="Live Analysis Log", font=FONT_BOLD, fg=FG_DIM, bg=BG,
                 anchor=tk.W).grid(row=0, column=0, sticky="w", pady=(0, 4))

        self.log_text = scrolledtext.ScrolledText(
            left, bg=BG_DARK, fg=FG, font=MONO, insertbackground=FG,
            relief=tk.FLAT, borderwidth=0, wrap=tk.WORD, state=tk.DISABLED,
        )
        self.log_text.grid(row=1, column=0, sticky="nsew")
        left.columnconfigure(0, weight=1)

        self.log_text.tag_configure("spike", foreground=RED)
        self.log_text.tag_configure("net", foreground=ORANGE)
        self.log_text.tag_configure("file", foreground=ACCENT)
        self.log_text.tag_configure("info", foreground=FG_DIM)

        right = tk.Frame(body, bg=BG)
        right.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        right.rowconfigure(0, weight=1)
        right.columnconfigure(0, weight=1)

        self.report_canvas = tk.Canvas(right, bg=BG, highlightthickness=0)
        scrollbar = ttk.Scrollbar(right, orient=tk.VERTICAL, command=self.report_canvas.yview)

        self.report_frame = tk.Frame(self.report_canvas, bg=BG)
        self.report_frame.bind("<Configure>",
            lambda e: self.report_canvas.configure(scrollregion=self.report_canvas.bbox("all")))
        self.report_canvas.create_window((0, 0), window=self.report_frame, anchor="nw")
        self.report_canvas.configure(yscrollcommand=scrollbar.set)

        self.report_canvas.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")

        self.report_canvas.bind_all("<MouseWheel>",
            lambda e: self.report_canvas.yview_scroll(int(-1*(e.delta/120)), "units"))

        self._show_placeholder()

        bottom = tk.Frame(self.root, bg=BG_DARK, height=50)
        bottom.pack(fill=tk.X, side=tk.BOTTOM)
        bottom.pack_propagate(False)

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("G.TButton", background=GREEN, foreground=BG_DARK,
                         font=FONT_BOLD, padding=8)
        style.map("G.TButton", background=[("active", "#74c78b")])
        style.configure("B.TButton", background=ACCENT, foreground=BG_DARK,
                         font=FONT_BOLD, padding=8)
        style.map("B.TButton", background=[("active", "#6da0e0")])

        self.btn_graph = ttk.Button(bottom, text="📊 View Graph", style="B.TButton",
                                     command=self._open_graph, state=tk.DISABLED)
        self.btn_graph.pack(side=tk.RIGHT, padx=8, pady=8)

        self.btn_save = ttk.Button(bottom, text="💾 Save Report", style="G.TButton",
                                    command=self._save_report, state=tk.DISABLED)
        self.btn_save.pack(side=tk.RIGHT, padx=8, pady=8)

        self.bottom_status = tk.Label(
            bottom, text="Target: " + self.target, font=FONT_SM,
            fg=FG_DIM, bg=BG_DARK, anchor=tk.W
        )
        self.bottom_status.pack(side=tk.LEFT, padx=16)

    def _show_placeholder(self):
        for w in self.report_frame.winfo_children():
            w.destroy()
        tk.Label(
            self.report_frame, text="⏳\n\nAnalysis in progress...\n\nResults will appear here",
            font=("Segoe UI", 12), fg=FG_DIM, bg=BG, justify=tk.CENTER,
        ).pack(expand=True, fill=tk.BOTH, pady=80)

    def _poll_log(self):
        while True:
            try:
                msg = self.log_queue.get_nowait()
            except queue.Empty:
                break
            tag = "info"
            if "SPIKE" in msg or "spike" in msg:
                tag = "spike"
            elif "Network" in msg or "network" in msg:
                tag = "net"
            elif "File event" in msg or "file" in msg.lower():
                tag = "file"

            self.log_text.configure(state=tk.NORMAL)
            self.log_text.insert(tk.END, msg + "\n", tag)
            self.log_text.see(tk.END)
            self.log_text.configure(state=tk.DISABLED)

        if self.result is None:
            self.root.after(100, self._poll_log)

    def _start_analysis(self):
        self.root.after(100, self._poll_log)
        t = threading.Thread(target=self._run_analysis, daemon=True)
        t.start()

    def _run_analysis(self):
        from analyzer import DynamicAnalyzer
        from static_analysis import extract_cfg, compute_static_metrics
        from risk_engine import calculate_risk, classify

        analyzer = DynamicAnalyzer(self.target, duration=self.duration)
        result = analyzer.run()

        static_features = {}
        cfg_data = None
        if self.run_static:
            cfg_data = extract_cfg(self.target)
            static_features = compute_static_metrics(cfg_data)
            result["static_analysis"] = static_features

        risk_score = calculate_risk(result, static_features)
        threat_level = classify(risk_score)
        result["risk_score"] = risk_score
        result["threat_level"] = threat_level

        self.result = result
        self.risk_score = risk_score
        self.threat_level = threat_level
        self.cfg_data = cfg_data

        self.root.after(0, self._show_report)

    def _show_report(self):
        self._poll_log()

        result = self.result
        color = THREAT_COLORS.get(self.threat_level, FG)

        if result["suspicious"]:
            self.status_label.configure(text="⚠ SUSPICIOUS", fg=RED)
        else:
            self.status_label.configure(text="✔ CLEAN", fg=GREEN)

        self.risk_badge.configure(
            text=f"  {self.threat_level}  ─  {self.risk_score}  ",
            bg=color, fg=BG_DARK
        )

        self.btn_save.configure(state=tk.NORMAL)
        self.btn_graph.configure(state=tk.NORMAL)
        self.bottom_status.configure(
            text=f"Target: {self.target}  │  Duration: {self.duration}s  │  Done"
        )

        for w in self.report_frame.winfo_children():
            w.destroy()

        def card(parent, title, content_widgets_fn):
            frame = tk.Frame(parent, bg=BG_CARD, highlightbackground=BORDER,
                             highlightthickness=1)
            frame.pack(fill=tk.X, pady=6, padx=4)
            tk.Label(frame, text=title, font=FONT_BOLD, fg=ACCENT, bg=BG_CARD,
                     anchor=tk.W).pack(fill=tk.X, padx=12, pady=(10, 4))
            sep = tk.Frame(frame, bg=BORDER, height=1)
            sep.pack(fill=tk.X, padx=12)
            body = tk.Frame(frame, bg=BG_CARD)
            body.pack(fill=tk.X, padx=12, pady=(6, 10))
            content_widgets_fn(body)
            return frame

        def risk_card(body):
            score_color = THREAT_COLORS.get(self.threat_level, FG)
            tk.Label(body, text=str(self.risk_score), font=FONT_XL,
                     fg=score_color, bg=BG_CARD).pack(side=tk.LEFT, padx=(0, 12))
            info = tk.Frame(body, bg=BG_CARD)
            info.pack(side=tk.LEFT, fill=tk.X)
            tk.Label(info, text=self.threat_level + " RISK",
                     font=FONT_BOLD, fg=score_color, bg=BG_CARD,
                     anchor=tk.W).pack(anchor=tk.W)
            tk.Label(info, text="Composite score from dynamic + static signals",
                     font=FONT_SM, fg=FG_DIM, bg=BG_CARD,
                     anchor=tk.W).pack(anchor=tk.W)

        card(self.report_frame, "🎯 Risk Score", risk_card)

        def target_card(body):
            loc = result.get("target_location") or "Unknown"
            tk.Label(body, text=loc, font=MONO, fg=FG, bg=BG_CARD,
                     anchor=tk.W, wraplength=350).pack(anchor=tk.W)

        card(self.report_frame, "📁 Target", target_card)

        def indicators_card(body):
            indicators = [
                ("CPU Spike", result.get("cpu_spike", False)),
                ("Network Activity", bool(result.get("network_activity"))),
                ("File Activity", bool(result.get("file_activity"))),
                ("Flagged Functions", bool(result.get("flagged_functions"))),
            ]
            for name, active in indicators:
                row = tk.Frame(body, bg=BG_CARD)
                row.pack(fill=tk.X, pady=1)
                dot = "●" if active else "○"
                dot_color = RED if active else FG_DIM
                tk.Label(row, text=dot, font=FONT, fg=dot_color, bg=BG_CARD,
                         width=2).pack(side=tk.LEFT)
                tk.Label(row, text=name, font=FONT, fg=FG if active else FG_DIM,
                         bg=BG_CARD, anchor=tk.W).pack(side=tk.LEFT)

        card(self.report_frame, "🔍 Indicators", indicators_card)

        net = result.get("network_activity", [])
        if net:
            def net_card(body):
                for ep in net:
                    tk.Label(body, text="→  " + ep, font=MONO, fg=ORANGE,
                             bg=BG_CARD, anchor=tk.W).pack(anchor=tk.W, pady=1)
            card(self.report_frame, f"🌐 Network Connections ({len(net)})", net_card)

        flagged = result.get("flagged_functions", [])
        if flagged:
            def flag_card(body):
                for fn in flagged:
                    tk.Label(body, text="⚡ " + fn, font=MONO, fg=RED,
                             bg=BG_CARD, anchor=tk.W).pack(anchor=tk.W, pady=1)
            card(self.report_frame, f"⚠ Flagged Functions ({len(flagged)})", flag_card)

        files = result.get("file_activity", [])
        if files:
            def file_card(body):
                for ev in files:
                    action = ev.get("action", "?")
                    fname = ev.get("file", "?")
                    color = ORANGE if any(fname.endswith(e) for e in (
                        ".exe", ".dll", ".bat", ".cmd"
                    )) else FG_DIM
                    tk.Label(body, text=f"{action}: {fname}", font=MONO,
                             fg=color, bg=BG_CARD, anchor=tk.W).pack(anchor=tk.W, pady=1)
            card(self.report_frame, f"📄 File Activity ({len(files)})", file_card)

    def _open_graph(self):
        from graph_visualizer import launch as launch_vis, build_dynamic_graph_data
        report_info = {"risk_score": self.risk_score, "threat_level": self.threat_level}
        if hasattr(self, "cfg_data") and self.cfg_data and self.cfg_data.get("nodes"):
            data = self.cfg_data
        else:
            data = build_dynamic_graph_data(self.result)
        threading.Thread(
            target=lambda: launch_vis(data=data, report_info=report_info),
            daemon=True,
        ).start()

    def _save_report(self):
        from tkinter import filedialog
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("All", "*.*")],
            title="Save Analysis Report",
        )
        if path:
            with open(path, "w") as f:
                json.dump(self.result, f, indent=4)
            self.bottom_status.configure(text=f"Report saved to {path}")


def launch_gui(target, duration=15, static=False, visualize=False, verbose=False):
    root = tk.Tk()
    AnalysisApp(root, target, duration, static, visualize, verbose)
    root.mainloop()
