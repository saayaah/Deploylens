"""Command-line entry point: scan a ZIP or a directory and print a JSON or CSV report.

  python -m app.cli scan ../fixtures/demo_project --format csv
  python -m app.cli scan project.zip --format json
"""
from __future__ import annotations

import argparse
import os
import sys

from .analyzer import analyze_archive, analyze_directory
from .report_export import to_csv, to_json
from .zip_safety import ArchiveError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="deploylens")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="scan a ZIP archive or directory")
    scan.add_argument("target")
    scan.add_argument("--format", choices=["json", "csv"], default="json")
    args = parser.parse_args(argv)

    try:
        if os.path.isdir(args.target):
            report = analyze_directory(args.target)
        else:
            with open(args.target, "rb") as fh:
                report = analyze_archive(fh.read(), os.path.basename(args.target))
    except ArchiveError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    sys.stdout.write(to_json(report) if args.format == "json" else to_csv(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
