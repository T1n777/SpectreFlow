import os
import ctypes
import json
import logging
import queue
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog

import config

BG = "#1e1e2e"
BG_DARK = "#181825"
BG_CARD = "#313244"
FG = "#cdd6f4"
FG_DIM = "#a6adc8"
ACCENT = "#89b4fa"
GREEN = "#a6e3a1"
RED = "#f38ba8"
ORANGE = "#fab387"
YELLOW = "#f9e2af"
BORDER = "#45475a"

THREAT_COLORS = {"HIGH": RED, "MEDIUM": ORANGE, "LOW": GREEN}

FONT = ("Segoe UI", 10)
FONT_BOLD = ("Segoe UI", 10, "bold")
FONT_SM = ("Segoe UI", 9)
FONT_LG = ("Segoe UI", 14, "bold")
FONT_XL = ("Segoe UI", 22, "bold")
MONO = ("Consolas", 9)


class QueueHandler(logging.Handler):

    def __init__(self, log_queue):
        super().__init__()
        self.log_queue = log_queue

    def emit(self, record):
        self.log_queue.put(self.format(record))


class AnalysisApp:

    def __init__(self, root, target, duration, run_static, run_visualize, verbose):
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
        handler = QueueHandler(self.log_queue)
        handler.setFormatter(logging.Formatter(
            "%(asctime)s │ %(name)-30s │ %(message)s", datefmt="%H:%M:%S"
        ))
        root_logger = logging.getLogger()
        if self.verbose:
            root_logger.setLevel(logging.DEBUG)
        else:
            root_logger.setLevel(logging.INFO)
        root_logger.addHandler(handler)

    def _build_ui(self):
        header = tk.Frame(self.root, bg=BG_DARK, height=60)
        header.pack(fill=tk.X)
        header.pack_propagate(False)

        tk.Label(header, text="⬡ SpectreFlow", font=FONT_LG,
                 fg=ACCENT, bg=BG_DARK).pack(side=tk.LEFT, padx=16, pady=10)

        self.status_label = tk.Label(
            header, text="⏳ Analyzing...", font=FONT_BOLD,
            fg=YELLOW, bg=BG_DARK,
        )
        self.status_label.pack(side=tk.LEFT, padx=20)

        self.risk_badge = tk.Label(header, text="", font=FONT_LG,
                                   fg=BG, bg=BG_DARK)
        self.risk_badge.pack(side=tk.RIGHT, padx=16, pady=10)

        body = tk.Frame(self.root, bg=BG)
        body.pack(fill=tk.BOTH, expand=True, padx=16, pady=(8, 16))
        body.columnconfigure(0, weight=3, minsize=420)
        body.columnconfigure(1, weight=2, minsize=300)
        body.rowconfigure(0, weight=1)

        left = tk.Frame(body, bg=BG)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        left.rowconfigure(1, weight=1)
        left.columnconfigure(0, weight=1)

        tk.Label(left, text="Live Analysis Log", font=FONT_BOLD,
                 fg=FG_DIM, bg=BG, anchor=tk.W).grid(
            row=0, column=0, sticky="w", pady=(0, 4))

        self.log_text = scrolledtext.ScrolledText(
            left, bg=BG_DARK, fg=FG, font=MONO, insertbackground=FG,
            relief=tk.FLAT, borderwidth=0, wrap=tk.WORD, state=tk.DISABLED,
        )
        self.log_text.grid(row=1, column=0, sticky="nsew")

        self.log_text.vbar.configure(
            bg=BG_CARD, troughcolor=BG_DARK,
            activebackground=ACCENT, highlightbackground=BG_DARK,
            bd=0, width=12,
        )

        self.log_text.tag_configure("spike", foreground=RED)
        self.log_text.tag_configure("net", foreground=ORANGE)
        self.log_text.tag_configure("file", foreground=ACCENT)
        self.log_text.tag_configure("info", foreground=FG_DIM)

        right = tk.Frame(body, bg=BG)
        right.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        right.rowconfigure(0, weight=1)
        right.columnconfigure(0, weight=1)

        self.report_canvas = tk.Canvas(right, bg=BG, highlightthickness=0)
        scrollbar = ttk.Scrollbar(right, orient=tk.VERTICAL,
                                  command=self.report_canvas.yview)

        self.report_frame = tk.Frame(self.report_canvas, bg=BG)
        self.report_frame.bind(
            "<Configure>",
            lambda e: self.report_canvas.configure(
                scrollregion=self.report_canvas.bbox("all")),
        )
        self.report_canvas.create_window((0, 0), window=self.report_frame,
                                         anchor="nw")
        self.report_canvas.configure(yscrollcommand=scrollbar.set)
        self.report_canvas.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")

        self.report_canvas.bind_all(
            "<MouseWheel>",
            lambda e: self.report_canvas.yview_scroll(
                int(-1 * (e.delta / 120)), "units"),
        )

        self._show_placeholder()

        bottom = tk.Frame(self.root, bg=BG_DARK, height=70)
        bottom.pack(fill=tk.X, side=tk.BOTTOM)
        bottom.pack_propagate(False)

        style = ttk.Style()
        style.theme_use("clam")

        style.configure("Vertical.TScrollbar",
                        background=BG_CARD, troughcolor=BG_DARK,
                        arrowcolor=FG_DIM, bordercolor=BG_DARK,
                        lightcolor=BG_CARD, darkcolor=BG_DARK)
        style.map("Vertical.TScrollbar",
                  background=[("active", ACCENT), ("!disabled", BG_CARD)])

        style.configure("G.TButton", background=GREEN, foreground=BG_DARK,
                        font=FONT_BOLD, padding=8)
        style.map("G.TButton", background=[("active", "#74c78b")])

        style.configure("B.TButton", background=ACCENT, foreground=BG_DARK,
                        font=FONT_BOLD, padding=8)
        style.map("B.TButton", background=[("active", "#6da0e0")])

        self.btn_graph = ttk.Button(bottom, text="📊 View Graph",
                                    style="B.TButton",
                                    command=self._open_graph,
                                    state=tk.DISABLED)
        self.btn_graph.pack(side=tk.RIGHT, padx=8, pady=8)

        self.btn_save = ttk.Button(bottom, text="💾 Save Report",
                                   style="G.TButton",
                                   command=self._save_report,
                                   state=tk.DISABLED)
        self.btn_save.pack(side=tk.RIGHT, padx=8, pady=8)

        self.bottom_status = tk.Label(
            bottom, text="Target: " + self.target, font=FONT_SM,
            fg=FG_DIM, bg=BG_DARK, anchor=tk.W,
        )
        self.bottom_status.pack(side=tk.LEFT, padx=16)

    def _show_placeholder(self):
        for w in self.report_frame.winfo_children():
            w.destroy()
        tk.Label(
            self.report_frame,
            text="⏳\n\nAnalysis in progress...\n\nResults will appear here",
            font=("Segoe UI", 12), fg=FG_DIM, bg=BG, justify=tk.CENTER,
        ).pack(expand=True, fill=tk.BOTH, pady=80)

    def _poll_log(self):
        while True:
            try:
                msg = self.log_queue.get_nowait()
            except queue.Empty:
                break

            if "SPIKE" in msg or "spike" in msg:
                tag = "spike"
            elif "Network" in msg or "network" in msg:
                tag = "net"
            elif "File event" in msg or "file" in msg.lower():
                tag = "file"
            else:
                tag = "info"

            self.log_text.configure(state=tk.NORMAL)
            self.log_text.insert(tk.END, msg + "\n", tag)
            self.log_text.see(tk.END)
            self.log_text.configure(state=tk.DISABLED)

        if self.result is None:
            self.root.after(100, self._poll_log)

    def _start_analysis(self):
        self.root.after(100, self._poll_log)
        threading.Thread(target=self._run_analysis, daemon=True).start()

    def _run_analysis(self):
        from analyzer import DynamicAnalyzer
        from static_analysis import extract_cfg, compute_static_metrics
        from risk_engine import calculate_risk, classify

        analyzer = DynamicAnalyzer(self.target, duration=self.duration)
        result = analyzer.run()

        static_features = {}
        self.cfg_data = None
        if self.run_static:
            self.cfg_data = extract_cfg(self.target)
            static_features = compute_static_metrics(self.cfg_data)
            result["static_analysis"] = static_features

        risk_score = calculate_risk(result, static_features)
        threat_level = classify(risk_score)
        result["risk_score"] = risk_score
        result["threat_level"] = threat_level

        self.result = result
        self.risk_score = risk_score
        self.threat_level = threat_level

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
            text=f"  {self.threat_level}  ─  {self.risk_score}/32  ",
            bg=color, fg=BG_DARK,
        )

        self.btn_save.configure(state=tk.NORMAL)
        self.btn_graph.configure(state=tk.NORMAL)
        self.bottom_status.configure(
            text=f"Target: {self.target}  │  Duration: {self.duration}s  │  Done"
        )

        for w in self.report_frame.winfo_children():
            w.destroy()

        def round_rect(canvas, x1, y1, x2, y2, r=14, **kw):
            pts = [
                x1+r, y1, x2-r, y1, x2, y1, x2, y1+r,
                x2, y2-r, x2, y2, x2-r, y2, x1+r, y2,
                x1, y2, x1, y2-r, x1, y1+r, x1, y1,
            ]
            return canvas.create_polygon(pts, smooth=True, **kw)

        def card(parent, title, content_fn):
            outer = tk.Frame(parent, bg=BG)
            outer.pack(fill=tk.X, pady=6, padx=4)

            cv = tk.Canvas(outer, bg=BG, highlightthickness=0, height=0)
            cv.pack(fill=tk.X)

            inner = tk.Frame(cv, bg=BG_CARD)
            tk.Label(inner, text=title, font=FONT_BOLD, fg=ACCENT,
                     bg=BG_CARD, anchor=tk.W).pack(fill=tk.X, padx=12, pady=(10, 4))
            tk.Frame(inner, bg=BORDER, height=1).pack(fill=tk.X, padx=12)
            body = tk.Frame(inner, bg=BG_CARD)
            body.pack(fill=tk.X, padx=12, pady=(6, 10))
            content_fn(body)

            win = cv.create_window(0, 0, window=inner, anchor="nw")

            def resize(event=None):
                inner.update_idletasks()
                w = max(inner.winfo_reqwidth(), outer.winfo_width())
                h = inner.winfo_reqheight()
                cv.configure(width=w, height=h)
                cv.itemconfigure(win, width=w)
                cv.delete("bg")
                round_rect(cv, 0, 0, w, h, r=14,
                           fill=BG_CARD, outline=BORDER, width=1, tags="bg")
                cv.tag_lower("bg")

            inner.bind("<Configure>", resize)
            outer.bind("<Configure>", resize)
            outer.after(50, resize)
            return outer

        def risk_card(body):
            score_color = THREAT_COLORS.get(self.threat_level, FG)
            tk.Label(body, text=f"{self.risk_score}/32", font=FONT_XL,
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
            location = result.get("target_location") or "Unknown"
            tk.Label(body, text=location,
                     font=MONO, fg=FG, bg=BG_CARD, anchor=tk.W,
                     wraplength=350).pack(anchor=tk.W)

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
                if active:
                    dot = "●"
                    dot_color = RED
                else:
                    dot = "○"
                    dot_color = FG_DIM
                tk.Label(row, text=dot, font=FONT, fg=dot_color,
                         bg=BG_CARD, width=2).pack(side=tk.LEFT)
                if active:
                    text_color = FG
                else:
                    text_color = FG_DIM
                tk.Label(row, text=name, font=FONT,
                         fg=text_color,
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
                    fname = ev.get("file", "?")
                    _, ext = os.path.splitext(fname)
                    if ext.lower() in config.SUSPICIOUS_EXTENSIONS:
                        text_color = ORANGE
                    else:
                        text_color = FG_DIM
                    action = ev.get("action", "?")
                    tk.Label(body, text=f"{action}: {fname}",
                             font=MONO, fg=text_color, bg=BG_CARD,
                             anchor=tk.W).pack(anchor=tk.W, pady=1)
            card(self.report_frame, f"📄 File Activity ({len(files)})", file_card)

    def _open_graph(self):
        from graph_visualizer import launch as launch_vis, build_dynamic_graph_data

        report_info = {"risk_score": self.risk_score,
                       "threat_level": self.threat_level}

        if hasattr(self, "cfg_data") and self.cfg_data and self.cfg_data.get("nodes"):
            data = self.cfg_data
        else:
            data = build_dynamic_graph_data(self.result)

        threading.Thread(
            target=lambda: launch_vis(data=data, report_info=report_info),
            daemon=True,
        ).start()

    def _save_report(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("All", "*.*")],
            title="Save Analysis Report",
        )
        if path:
            with open(path, "w") as f:
                json.dump(self.result, f, indent=4)
            self.bottom_status.configure(text=f"Report saved to {path}")


def _set_dark_title_bar(root):
    root.update_idletasks()
    try:
        hwnd = ctypes.windll.user32.GetParent(root.winfo_id())
        ctypes.windll.dwmapi.DwmSetWindowAttribute(
            hwnd, 20, ctypes.byref(ctypes.c_int(1)), ctypes.sizeof(ctypes.c_int),
        )
    except Exception:
        pass


def launch_gui(target, duration=15, static=False, visualize=False, verbose=False):
    root = tk.Tk()
    _set_dark_title_bar(root)
    AnalysisApp(root, target, duration, static, visualize, verbose)
    root.mainloop()
