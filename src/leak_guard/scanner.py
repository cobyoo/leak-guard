"""Core scanning engine."""

from dataclasses import dataclass
from pathlib import Path

from .patterns import SecretPattern, get_patterns

BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
    ".woff", ".woff2", ".ttf", ".eot",
    ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".pyc", ".pyo", ".so", ".dll", ".dylib",
    ".exe", ".bin", ".dat",
}

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    ".mypy_cache", ".pytest_cache", "dist", "build", ".next",
    ".nuxt", "vendor", ".tox", "egg-info",
}


@dataclass
class Finding:
    file: str
    line_number: int
    line: str
    pattern_name: str
    severity: str
    matched_text: str


def is_binary(path: Path) -> bool:
    return path.suffix.lower() in BINARY_EXTENSIONS


def scan_content(
    content: str,
    filename: str = "<stdin>",
    patterns: list[SecretPattern] | None = None,
) -> list[Finding]:
    if patterns is None:
        patterns = get_patterns()

    findings: list[Finding] = []

    for line_number, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("//"):
            continue

        for pat in patterns:
            match = pat.pattern.search(line)
            if match:
                findings.append(Finding(
                    file=filename,
                    line_number=line_number,
                    line=line.rstrip(),
                    pattern_name=pat.name,
                    severity=pat.severity,
                    matched_text=match.group(0),
                ))

    return findings


def scan_file(path: Path, patterns: list[SecretPattern] | None = None) -> list[Finding]:
    if is_binary(path):
        return []

    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except (OSError, PermissionError):
        return []

    return scan_content(content, filename=str(path), patterns=patterns)


def scan_directory(
    root: Path,
    patterns: list[SecretPattern] | None = None,
) -> list[Finding]:
    findings: list[Finding] = []

    for path in root.rglob("*"):
        if any(skip in path.parts for skip in SKIP_DIRS):
            continue
        if path.is_file() and not is_binary(path):
            findings.extend(scan_file(path, patterns))

    return findings


def scan_staged_files(patterns: list[SecretPattern] | None = None) -> list[Finding]:
    """Scan git staged files only (for pre-commit hook)."""
    import subprocess

    result = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        return []

    findings: list[Finding] = []
    for filename in result.stdout.strip().splitlines():
        if not filename:
            continue
        path = Path(filename)
        if path.exists():
            findings.extend(scan_file(path, patterns))

    return findings
