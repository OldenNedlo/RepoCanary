from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
import fnmatch
import json
import re

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}

SKIP_DIRS = {
    ".git", ".hg", ".svn", ".venv", "venv", "node_modules",
    "dist", "build", "__pycache__", ".pytest_cache", ".mypy_cache",
}

TEXT_SUFFIXES = {
    ".md", ".rst", ".txt", ".py", ".js", ".ts", ".tsx", ".jsx",
    ".json", ".toml", ".yaml", ".yml", ".ini", ".cfg", ".sh",
    ".ps1", ".bat", ".html", ".css", ".java", ".go", ".rs",
    ".c", ".h", ".cpp", ".hpp",
}

COMMUNITY_FILES = {
    "license": ("LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING"),
    "security": ("SECURITY.md",),
    "contributing": ("CONTRIBUTING.md", "CONTRIBUTING.rst"),
    "code-of-conduct": ("CODE_OF_CONDUCT.md", "CODE-OF-CONDUCT.md"),
}

SENSITIVE_PATTERNS = {
    ".env", ".env.*", "id_rsa", "id_dsa", "id_ed25519",
    "*.pem", "*.p12", "*.pfx", "credentials.json",
    "service-account*.json",
}

MARKDOWN_LINK_RE = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
TODO_RE = re.compile(r"\b(TODO|FIXME)\b", re.IGNORECASE)
USES_RE = re.compile(r"^\s*(?:-\s*)?uses:\s*([^\s#]+)\s*$")
MOVING_REF_RE = re.compile(r"@(?:main|master|latest|develop|dev|head)$", re.IGNORECASE)


@dataclass(frozen=True)
class Finding:
    check: str
    severity: str
    message: str
    path: str | None = None
    line: int | None = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanResult:
    repository: str
    files_scanned: int
    findings: list[Finding]

    def to_dict(self) -> dict:
        counts = {key: 0 for key in SEVERITY_ORDER}
        for item in self.findings:
            counts[item.severity] += 1
        return {
            "repository": self.repository,
            "files_scanned": self.files_scanned,
            "finding_count": len(self.findings),
            "severity_counts": counts,
            "findings": [item.to_dict() for item in self.findings],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)

    def to_markdown(self) -> str:
        data = self.to_dict()
        lines = [
            "# RepoCanary Report",
            "",
            f"- Repository: `{self.repository}`",
            f"- Files scanned: **{self.files_scanned}**",
            f"- Findings: **{data['finding_count']}**",
            "",
        ]
        if not self.findings:
            lines.append("No findings.")
            return "\n".join(lines) + "\n"

        lines.extend([
            "| Severity | Check | Location | Finding |",
            "|---|---|---|---|",
        ])
        for item in self.findings:
            location = item.path or ""
            if item.line is not None:
                location += f":{item.line}"
            message = item.message.replace("|", "\\|")
            lines.append(
                f"| {item.severity.upper()} | `{item.check}` | `{location}` | "
                f"{message} |"
            )
        return "\n".join(lines) + "\n"


def _files(root: Path):
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        yield path


def _relative(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def _read_text(path: Path) -> str | None:
    if path.suffix.lower() not in TEXT_SUFFIXES and path.name not in {
        "Dockerfile", "Makefile", "requirements.txt"
    }:
        return None
    try:
        return path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return None


def _community_findings(root: Path) -> list[Finding]:
    names = {p.name for p in root.iterdir() if p.is_file()}
    findings = []
    for label, alternatives in COMMUNITY_FILES.items():
        if not any(name in names for name in alternatives):
            findings.append(Finding(
                check="community-file",
                severity="medium" if label in {"license", "security"} else "low",
                message=f"Missing recommended {label} file.",
            ))
    return findings


def _sensitive_filename(root: Path, path: Path) -> list[Finding]:
    for pattern in SENSITIVE_PATTERNS:
        if fnmatch.fnmatch(path.name.lower(), pattern.lower()):
            return [Finding(
                check="sensitive-filename",
                severity="high",
                message="Potentially sensitive filename is present in the repository.",
                path=_relative(root, path),
            )]
    return []


def _large_file(root: Path, path: Path, limit: int) -> list[Finding]:
    try:
        size = path.stat().st_size
    except OSError:
        return []
    if size > limit:
        return [Finding(
            check="large-file",
            severity="low",
            message=f"File is {size / (1024 * 1024):.1f} MiB.",
            path=_relative(root, path),
        )]
    return []


def _todos(root: Path, path: Path, text: str) -> list[Finding]:
    count = 0
    for line in text.splitlines():
        stripped = line.lstrip()
        if stripped.startswith(("#", "//", "/*", "*", "<!--", ";")):
            count += len(TODO_RE.findall(line))
    if not count:
        return []
    return [Finding(
        check="todo",
        severity="info" if count < 5 else "low",
        message=f"Contains {count} TODO/FIXME comment marker(s).",
        path=_relative(root, path),
    )]


def _markdown_links(root: Path, path: Path, text: str) -> list[Finding]:
    if path.suffix.lower() != ".md":
        return []
    findings = []
    for match in MARKDOWN_LINK_RE.finditer(text):
        target = match.group(1).strip()
        if not target or target.startswith(("http://", "https://", "mailto:", "#", "data:")):
            continue
        clean = target.split("#", 1)[0].split("?", 1)[0]
        if not clean:
            continue
        candidate = (path.parent / clean).resolve()
        try:
            candidate.relative_to(root.resolve())
        except ValueError:
            continue
        if not candidate.exists():
            findings.append(Finding(
                check="markdown-link",
                severity="medium",
                message=f"Broken relative Markdown link: {target}",
                path=_relative(root, path),
                line=text.count("\n", 0, match.start()) + 1,
            ))
    return findings


def _workflow_refs(root: Path, path: Path, text: str) -> list[Finding]:
    rel = _relative(root, path)
    if not rel.startswith(".github/workflows/") or path.suffix.lower() not in {".yml", ".yaml"}:
        return []
    findings = []
    for lineno, line in enumerate(text.splitlines(), 1):
        match = USES_RE.match(line)
        if match and MOVING_REF_RE.search(match.group(1)):
            findings.append(Finding(
                check="workflow-ref",
                severity="medium",
                message=f"Moving GitHub Action reference: {match.group(1)}",
                path=rel,
                line=lineno,
            ))
    return findings


def _requirements(root: Path, path: Path, text: str) -> list[Finding]:
    if path.name != "requirements.txt":
        return []
    findings = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(("#", "-", "git+", "http://", "https://")):
            continue
        if not re.search(r"(===|==|~=|>=|<=|!=|>|<)", line):
            findings.append(Finding(
                check="python-requirement",
                severity="low",
                message=f"Dependency has no version constraint: {line}",
                path=_relative(root, path),
                line=lineno,
            ))
    return findings


def scan_repository(root: str | Path, large_file_mib: int = 10) -> ScanResult:
    root = Path(root).resolve()
    if not root.is_dir():
        raise ValueError(f"Not a directory: {root}")

    findings = _community_findings(root)
    files_scanned = 0
    large_limit = large_file_mib * 1024 * 1024

    for path in _files(root):
        files_scanned += 1
        findings.extend(_sensitive_filename(root, path))
        findings.extend(_large_file(root, path, large_limit))

        text = _read_text(path)
        if text is None:
            continue

        findings.extend(_todos(root, path, text))
        findings.extend(_markdown_links(root, path, text))
        findings.extend(_workflow_refs(root, path, text))
        findings.extend(_requirements(root, path, text))

    findings.sort(
        key=lambda item: (
            -SEVERITY_ORDER[item.severity],
            item.path or "",
            item.line or 0,
            item.check,
        )
    )
    return ScanResult(str(root), files_scanned, findings)


def should_fail(result: ScanResult, threshold: str) -> bool:
    threshold = threshold.lower()
    if threshold == "never":
        return False
    floor = SEVERITY_ORDER[threshold]
    return any(SEVERITY_ORDER[item.severity] >= floor for item in result.findings)
