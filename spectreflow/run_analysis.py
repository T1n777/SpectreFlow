import argparse
import json
import logging
import sys

from analyzer import DynamicAnalyzer


def main():
    parser = argparse.ArgumentParser(
        description="SpectreFlow Dynamic Analyzer"
    )
    parser.add_argument("target", help="Path to target script / executable.")
    parser.add_argument("--duration", type=float, default=15, help="Monitor duration (s).")
    parser.add_argument("--output", type=str, default=None, help="Save JSON report to file.")
    parser.add_argument("--verbose", "-v", action="store_true", help="Debug logging.")
    args = parser.parse_args()

    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s │ %(name)-35s │ %(message)s",
        datefmt="%H:%M:%S",
    )

    analyzer = DynamicAnalyzer(args.target, duration=args.duration)
    result = analyzer.run()

    report = json.dumps(result, indent=4)
    print("\n" + "=" * 60)
    print("  SPECTREFLOW — DYNAMIC ANALYSIS REPORT")
    print("=" * 60)
    print(report)

    if args.output:
        with open(args.output, "w") as f:
            f.write(report)
        print(f"\nReport saved to {args.output}")

    sys.exit(1 if result["suspicious"] else 0)


if __name__ == "__main__":
    main()
