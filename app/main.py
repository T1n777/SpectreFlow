import argparse
import ctypes
import json
import logging
import sys
import tkinter as tk
from tkinter import filedialog, font as tkfont

from analyzer import DynamicAnalyzer
from static_analysis import extract_cfg, compute_static_metrics
from risk_engine import calculate_risk, classify
from pe_analysis import analyze_pe
from hash_lookup import check_hash
from vt_lookup import check_virustotal
from yara_scanner import scan_with_yara
from verdict_engine import render_verdict
from graph_visualizer import launch as launch_visualizer, build_dynamic_graph_data
from report_gui import launch_gui
import config

BG = "#1e1e2e"
BG_DARK = "#181825"
BG_CARD = "#313244"
ACCENT = "#89b4fa"
ACCENT_HOVER = "#6da0e0"
TEXT_PRIMARY = "#cdd6f4"
TEXT_DIM = "#a6adc8"
BORDER = "#45475a"


def _set_dark_title_bar(window):
    try:
        hwnd = ctypes.windll.user32.GetParent(window.winfo_id())
        DWMWA_USE_IMMERSIVE_DARK_MODE = 20
        ctypes.windll.dwmapi.DwmSetWindowAttribute(
            hwnd,
            DWMWA_USE_IMMERSIVE_DARK_MODE,
            ctypes.byref(ctypes.c_int(1)),
            ctypes.sizeof(ctypes.c_int),
        )
    except Exception:
        pass


def launch_welcome_window():
    selected_path = {"value": None}

    root = tk.Tk()
    root.title("SpectreFlow")
    root.configure(bg=BG)
    root.resizable(False, False)
    root.attributes("-topmost", True)
    root.update_idletasks()
    _set_dark_title_bar(root)

    win_w, win_h = 540, 520
    sx = root.winfo_screenwidth() // 2 - win_w // 2
    sy = root.winfo_screenheight() // 2 - win_h // 2
    root.geometry(f"{win_w}x{win_h}+{sx}+{sy}")

    title_font = tkfont.Font(family="Segoe UI", size=26, weight="bold")
    sub_font = tkfont.Font(family="Segoe UI", size=11)
    body_font = tkfont.Font(family="Segoe UI", size=10)
    btn_font = tkfont.Font(family="Segoe UI", size=13, weight="bold")

    header = tk.Frame(root, bg=BG_DARK, height=60)
    header.pack(fill="x")
    header.pack_propagate(False)
    tk.Label(
        header, text="⬡ SpectreFlow", font=("Segoe UI", 14, "bold"),
        fg=ACCENT, bg=BG_DARK,
    ).pack(side="left", padx=16, pady=10)

    tk.Label(root, text="👻  SpectreFlow", font=title_font,
             fg=ACCENT, bg=BG).pack(pady=(28, 4))
    tk.Label(root, text="Dynamic / Static Malware Analysis Engine",
             font=sub_font, fg=TEXT_DIM, bg=BG).pack(pady=(0, 18))

    card = tk.Frame(root, bg=BG_CARD, highlightbackground=BORDER,
                    highlightthickness=1, padx=24, pady=18)
    card.pack(padx=30, fill="x")

    features = [
        ("🔬", "Real-time process, network & file-system monitoring"),
        ("📊", "Static binary analysis via radare2 / r2pipe"),
        ("📈", "Interactive control-flow graph visualiser"),
        ("📝", "One-click JSON report export"),
    ]
    for icon, text in features:
        row = tk.Frame(card, bg=BG_CARD)
        row.pack(anchor="w", pady=3)
        tk.Label(row, text=icon, font=body_font, bg=BG_CARD,
                 fg=TEXT_PRIMARY, width=3).pack(side="left")
        tk.Label(row, text=text, font=body_font, bg=BG_CARD,
                 fg=TEXT_PRIMARY, wraplength=420, justify="left").pack(side="left")

    tk.Label(root, text="v1.0  •  Made with 🤍 for Hackathon 2026",
             font=body_font, fg=TEXT_DIM, bg=BG).pack(pady=(16, 6))

    def on_choose_file():
        path = filedialog.askopenfilename(
            parent=root,
            title="SpectreFlow — Select a file to analyse",
            filetypes=[
                ("Executables",    "*.exe *.dll *.bat *.cmd"),
                ("Python scripts", "*.py"),
                ("All files",      "*.*"),
            ],
        )
        if path:
            selected_path["value"] = path
            root.destroy()

    btn = tk.Button(
        root, text="📂  Choose File", font=btn_font,
        fg="#ffffff", bg=ACCENT, activebackground=ACCENT_HOVER,
        activeforeground="#ffffff", relief="flat", cursor="hand2",
        padx=24, pady=10, command=on_choose_file,
    )
    btn.pack(pady=(18, 24))
    btn.bind("<Enter>", lambda e: btn.configure(bg=ACCENT_HOVER))
    btn.bind("<Leave>", lambda e: btn.configure(bg=ACCENT))

    root.mainloop()
    return selected_path["value"]


def run_cli_analysis(target, duration, static, visualize, output):
    analyzer = DynamicAnalyzer(target, duration=duration)
    result = analyzer.run()

    static_features = {}
    cfg_data = None
    if static:
        cfg_data = extract_cfg(target)
        static_features = compute_static_metrics(cfg_data)
        result["static_analysis"] = static_features

    pe_result = analyze_pe(target)
    if pe_result:
        result["pe_analysis"] = pe_result

    hash_result = check_hash(target)
    result["hash_lookup"] = hash_result

    vt_result = check_virustotal(target, config.VIRUSTOTAL_API_KEY)
    result["virustotal"] = vt_result

    yara_matches = scan_with_yara(target)
    if yara_matches:
        result["yara_matches"] = [m["rule"] for m in yara_matches]
        result["yara_details"] = yara_matches

    score_breakdown = calculate_risk(
        result, static_features,
        pe_result=pe_result,
        hash_result=hash_result,
        yara_matches=yara_matches,
        vt_result=vt_result,
    )
    risk_score = score_breakdown["total"]
    threat_level = classify(score_breakdown)
    result["risk_score"] = risk_score
    result["risk_breakdown"] = score_breakdown
    result["threat_level"] = threat_level

    verdict_obj = render_verdict(
        result, score_breakdown,
        pe_result=pe_result,
        hash_result=hash_result,
        vt_result=vt_result,
    )
    result["verdict"] = verdict_obj

    report = json.dumps(result, indent=4)
    print("\n" + "=" * 60)
    print("  SPECTREFLOW — ANALYSIS REPORT")
    print("=" * 60)
    print(report)

    print("\n" + "═" * 60)
    print("  SPECTREFLOW — FINAL VERDICT")
    print("═" * 60)
    v = verdict_obj
    print(f"  Verdict:    {v['verdict']}")
    print(f"  Confidence: {v['confidence_pct']}")
    print()
    print("  Reasons:")
    for reason in v["reasons"]:
        print(f"  • {reason}")
    print()
    print("  Summary:")
    print(f"  {v['summary']}")
    print("═" * 60)

    if output:
        with open(output, "w") as f:
            f.write(report)
        print(f"\nReport saved to {output}")

    if visualize:
        report_info = {"risk_score": risk_score, "threat_level": threat_level}
        if cfg_data and cfg_data.get("nodes"):
            graph_data = cfg_data
        else:
            graph_data = build_dynamic_graph_data(result)
        launch_visualizer(data=graph_data, report_info=report_info)

    return verdict_obj


def main():
    parser = argparse.ArgumentParser(
        description="SpectreFlow — Dynamic / Static Malware Analysis Engine"
    )
    parser.add_argument("target", nargs="?", default=None,
                        help="Path to target script / executable "
                             "(opens welcome window if omitted).")
    parser.add_argument("--duration", type=float, default=15,
                        help="Monitor duration in seconds (default: 15).")
    parser.add_argument("--output", type=str, default=None,
                        help="Save JSON report to file.")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Debug logging.")
    parser.add_argument("--static", action="store_true",
                        help="Run static analysis (r2pipe).")
    parser.add_argument("--visualize", action="store_true",
                        help="Launch graph GUI.")
    parser.add_argument("--no-gui", action="store_true",
                        help="Terminal-only output (no GUI).")
    args = parser.parse_args()

    if args.target is None:
        print("\nNo file path provided — launching SpectreFlow welcome window…")
        args.target = launch_welcome_window()
        if args.target is None:
            print("⚠  No file selected. Exiting gracefully — nothing to analyse.")
            sys.exit(0)

    if not args.no_gui:
        launch_gui(
            target=args.target,
            duration=args.duration,
            static=args.static,
            visualize=args.visualize,
            verbose=args.verbose,
        )
        return

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s │ %(name)-35s │ %(message)s",
        datefmt="%H:%M:%S",
    )

    target = args.target
    while True:
        verdict_obj = run_cli_analysis(
            target, args.duration, args.static, args.visualize, args.output,
        )

        print("\n" + "-" * 60)
        choice = input("  Analyze another file? (y/n): ").strip().lower()
        if choice not in ("y", "yes"):
            break

        new_path = input("  Enter file path (or press Enter for file picker): ").strip()
        if new_path:
            target = new_path
        else:
            picked = launch_welcome_window()
            if picked is None:
                print("  No file selected.")
                break
            target = picked
        print()

    if verdict_obj["verdict"] in ("MALICIOUS", "SUSPICIOUS"):
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
