from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
import fnmatch
import json
import re

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "dist", "build", "__pycache__", ".pytest_cache", ".mypy_cache"}
TEXT_SUFFIXES = {".md", ".rst", ".txt", ".py", ".js", ".ts", ".json", ".toml", ".yaml", ".yml", ".ini", ".cfg", ".sh", ".ps1", ".bat", ".html", ".css", ".java", ".go", ".rs", ".c", ".h", ".cpp", ".hpp"}
COMMUNITY_FILES = {
    "license": ("LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING"),
    "security": ("SECURITY.md",),
    "contributing": ("CONTRIBUTING.md", "CONTRIBUTING.rst"),
    "code-of-conduct": ("CODE_OF_CONDUCT.md", "CODE-OF-CONDUCT.md"),
}
SENSITIVE_PATTERNS = {".env", ".env.*", "id_rsa", "id_dsa", "id_ed25519", "*.pem", "*.p12", "*.pfx", "credentials.json", "service-account*.json"}
MARKDOWN_LINK_RE = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
USES_RE = re.compile(r"^\s*(?:-\s*)?uses:\s*([^\s#]+)\s*$")
MOVING_REF_RE = re.compile(r"@(?:main|master|latest|develop|dev|head)$", re.IGNORECASE)
TODO_RE = re.compile(r"\b(TODO|FIXME)\b", re.IGNORECASE)

@dataclass(frozen=True)
class Finding:
    check: str
    severity: str
    message: str
    path: str | None = None
    line: int | None = None
    def to_dict(self): return asdict(self)

@dataclass
class ScanResult:
    repository: str
    files_scanned: int
    findings: list[Finding]
    def to_dict(self):
        counts = {k: 0 for k in SEVERITY_ORDER}
        for item in self.findings: counts[item.severity] += 1
        return {"repository": self.repository, "files_scanned": self.files_scanned, "finding_count": len(self.findings), "severity_counts": counts, "findings": [x.to_dict() for x in self.findings]}
    def to_json(self): return json.dumps(self.to_dict(), indent=2, sort_keys=True)
    def to_markdown(self):
        lines = ["# RepoCanary Report", "", f"- Repository: `{self.repository}`", f"- Files scanned: **{self.files_scanned}**", f"- Findings: **{len(self.findings)}**", ""]
        for item in self.findings:
            loc = item.path or ""
            if item.line is not None: loc += f":{item.line}"
            lines.append(f"- **{item.severity.upper()}** `{item.check}` `{loc}`: {item.message}")
        if not self.findings: lines.append("No findings.")
        return "\n".join(lines) + "\n"

def _files(root: Path):
    for path in root.rglob("*"):
        if path.is_file() and not any(part in SKIP_DIRS for part in path.parts):
            yield path

def _rel(root, path): return path.relative_to(root).as_posix()

def _read(path):
    if path.suffix.lower() not in TEXT_SUFFIXES and path.name != "requirements.txt": return None
    try: return path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError): return None

def scan_repository(root: str | Path, large_file_mib: int = 10) -> ScanResult:
    root = Path(root).resolve()
    if not root.is_dir(): raise ValueError(f"Not a directory: {root}")
    findings = []
    names = {p.name for p in root.iterdir() if p.is_file()}
    for label, alternatives in COMMUNITY_FILES.items():
        if not any(x in names for x in alternatives):
            findings.append(Finding("community-file", "medium" if label in {"license", "security"} else "low", f"Missing recommended {label} file."))
    count = 0
    limit = large_file_mib * 1024 * 1024
    for path in _files(root):
        count += 1
        rel = _rel(root, path)
        for pattern in SENSITIVE_PATTERNS:
            if fnmatch.fnmatch(path.name.lower(), pattern.lower()): findings.append(Finding("sensitive-filename", "high", "Potentially sensitive filename is present in the repository.", rel)); break
        if path.stat().st_size > limit: findings.append(Finding("large-file", "low", "File exceeds configured large-file threshold.", rel))
        text = _read(path)
        if text is None: continue
        if path.suffix.lower() == ".md":
            for m in MARKDOWN_LINK_RE.finditer(text):
                target = m.group(1).strip()
                if not target or target.startswith(("http://", "https://", "mailto:", "#", "data:")): continue
                clean = target.split("#",1)[0].split("?",1)[0]
                candidate = (path.parent / clean).resolve()
                try: candidate.relative_to(root)
                except ValueError: continue
                if clean and not candidate.exists(): findings.append(Finding("markdown-link", "medium", f"Broken relative Markdown link: {target}", rel, text.count("\n",0,m.start())+1))
        if rel.startswith(".github/workflows/"):
            for lineno, line in enumerate(text.splitlines(), 1):
                m = USES_RE.match(line)
                if m and MOVING_REF_RE.search(m.group(1)): findings.append(Finding("workflow-ref", "medium", f"Moving GitHub Action reference: {m.group(1)}", rel, lineno))
        if path.name == "requirements.txt":
            for lineno, raw in enumerate(text.splitlines(),1):
                line = raw.strip()
                if line and not line.startswith(("#","-","git+","http://","https://")) and not re.search(r"(===|==|~=|>=|<=|!=|>|<)", line): findings.append(Finding("python-requirement", "low", f"Dependency has no version constraint: {line}", rel, lineno))
        todo_count = sum(len(TODO_RE.findall(line)) for line in text.splitlines() if line.lstrip().startswith(("#","//","/*","*","<!--",";")))
        if todo_count: findings.append(Finding("todo", "info" if todo_count < 5 else "low", f"Contains {todo_count} TODO/FIXME comment marker(s).", rel))
    findings.sort(key=lambda x: (-SEVERITY_ORDER[x.severity], x.path or "", x.line or 0, x.check))
    return ScanResult(str(root), count, findings)

def should_fail(result: ScanResult, threshold: str) -> bool:
    if threshold == "never": return False
    floor = SEVERITY_ORDER[threshold]
    return any(SEVERITY_ORDER[x.severity] >= floor for x in result.findings)
