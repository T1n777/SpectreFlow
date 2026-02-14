"""
SpectreFlow — Dynamic Analysis CLI
Run: python run_analysis.py <target_script> [--duration SECONDS]
"""

import argparse
import json
import logging
import sys

from analyzer import DynamicAnalyzer


def main():
    parser = argparse.ArgumentParser(
        description="SpectreFlow Dynamic Analyzer — monitor a process for suspicious behaviour."
    )
    parser.add_argument(
        "target",
        help="Path to the target script / executable to analyze.",
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=15,
        help="Monitoring duration in seconds (default: 15).",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Optional path to save the JSON report to a file.",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose / debug logging.",
    )
    args = parser.parse_args()

    # ── Logging setup ────────────────────────────────────────────────
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s │ %(name)-35s │ %(message)s",
        datefmt="%H:%M:%S",
    )

    # ── Run analysis ─────────────────────────────────────────────────
    analyzer = DynamicAnalyzer(args.target, duration=args.duration)
    result = analyzer.run()

    # ── Output ───────────────────────────────────────────────────────
    report = json.dumps(result, indent=4)
    print("\n" + "=" * 60)
    print("  SPECTREFLOW — DYNAMIC ANALYSIS REPORT")
    print("=" * 60)
    print(report)

    if args.output:
        with open(args.output, "w") as f:
            f.write(report)
        print(f"\nReport saved to {args.output}")

    # Exit with code 1 if suspicious activity was detected
    sys.exit(1 if result["suspicious"] else 0)


if __name__ == "__main__":
    main()
