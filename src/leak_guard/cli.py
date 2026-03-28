"""Command-line interface for leak-guard."""

import argparse
import sys
from pathlib import Path

from .patterns import get_patterns
from .scanner import scan_directory, scan_file, scan_staged_files
from .reporter import report_text, report_json, print_summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="leak-guard",
        description="Lightweight secret detection tool with Korean service API key support",
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="File or directory to scan (default: current directory)",
    )
    parser.add_argument(
        "--pre-commit",
        action="store_true",
        help="Scan only git staged files (for pre-commit hook)",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output",
    )
    parser.add_argument(
        "--no-korean",
        action="store_true",
        help="Disable Korean service patterns",
    )
    parser.add_argument(
        "--severity",
        choices=["high", "medium", "low"],
        default=None,
        help="Minimum severity to report",
    )
    return parser


SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    patterns = get_patterns(include_korean=not args.no_korean)

    if args.pre_commit:
        findings = scan_staged_files(patterns)
    else:
        target = Path(args.path)
        if target.is_file():
            findings = scan_file(target, patterns)
        elif target.is_dir():
            findings = scan_directory(target, patterns)
        else:
            print(f"Error: {args.path} not found", file=sys.stderr)
            sys.exit(2)

    if args.severity:
        min_level = SEVERITY_ORDER[args.severity]
        findings = [f for f in findings if SEVERITY_ORDER[f.severity] >= min_level]

    use_color = not args.no_color and sys.stdout.isatty()

    if args.format == "json":
        print(report_json(findings))
    else:
        output = report_text(findings, use_color=use_color)
        if output:
            print(output)

    print_summary(findings, use_color=use_color)
