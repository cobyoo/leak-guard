"""Output formatting for scan results."""

import json
import sys
from .scanner import Finding

SEVERITY_COLORS = {
    "high": "\033[91m",    # red
    "medium": "\033[93m",  # yellow
    "low": "\033[94m",     # blue
}
RESET = "\033[0m"
BOLD = "\033[1m"


def report_text(findings: list[Finding], use_color: bool = True) -> str:
    if not findings:
        return ""

    lines: list[str] = []
    grouped: dict[str, list[Finding]] = {}
    for f in findings:
        grouped.setdefault(f.file, []).append(f)

    for filepath, file_findings in grouped.items():
        lines.append(f"\n{BOLD}{filepath}{RESET}" if use_color else f"\n{filepath}")

        for f in file_findings:
            color = SEVERITY_COLORS.get(f.severity, "") if use_color else ""
            reset = RESET if use_color else ""
            severity_label = f"[{f.severity.upper()}]"
            lines.append(
                f"  L{f.line_number}: {color}{severity_label}{reset} {f.pattern_name}"
            )
            # Show the line but mask the matched secret
            masked_line = f.line.replace(f.matched_text, "***REDACTED***")
            lines.append(f"    {masked_line.strip()}")

    return "\n".join(lines)


def report_json(findings: list[Finding]) -> str:
    return json.dumps(
        [
            {
                "file": f.file,
                "line": f.line_number,
                "severity": f.severity,
                "pattern": f.pattern_name,
                "content": f.line.replace(f.matched_text, "***REDACTED***"),
            }
            for f in findings
        ],
        indent=2,
        ensure_ascii=False,
    )


def print_summary(findings: list[Finding], use_color: bool = True) -> None:
    total = len(findings)
    high = sum(1 for f in findings if f.severity == "high")
    medium = sum(1 for f in findings if f.severity == "medium")
    low = sum(1 for f in findings if f.severity == "low")

    if total == 0:
        icon = "\u2705"
        print(f"\n{icon} No secrets detected.")
    else:
        icon = "\u26a0\ufe0f"
        print(f"\n{icon}  Found {total} potential secret(s): "
              f"{high} high, {medium} medium, {low} low")
        sys.exit(1)
