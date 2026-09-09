from __future__ import annotations
from pathlib import Path
import re
from .scanner import Finding,ScanResult,scan_repository
VERSION_RE=re.compile(r'^\s*version\s*=\s*["\']([^"\']+)["\']',re.MULTILINE)

def release_check(root:str|Path,large_file_mib:int=10,ignore_patterns:tuple[str,...]=())->ScanResult:
    root=Path(root).resolve()
    base=scan_repository(root,large_file_mib,ignore_patterns)
    findings=list(base.findings)
    for rel,severity,message in [
        ("CHANGELOG.md","medium","A changelog helps maintainers and users understand release changes."),
        (".github/workflows/ci.yml","medium","A CI workflow provides repeatable release confidence."),
        ("tests","medium","A test suite provides evidence that release behavior is checked."),
    ]:
        if not (root/rel).exists(): findings.append(Finding("release-readiness",severity,message,rel))
    pyproject=root/"pyproject.toml"
    if pyproject.exists():
        if not VERSION_RE.search(pyproject.read_text(encoding="utf-8")):
            findings.append(Finding("release-version","medium","pyproject.toml does not declare a project version.","pyproject.toml"))
    else:
        findings.append(Finding("release-metadata","low","No pyproject.toml found; verify release metadata for this project type."))
    if not (root/".github"/"PULL_REQUEST_TEMPLATE.md").exists():
        findings.append(Finding("maintainer-workflow","low","No pull request template found.",".github/PULL_REQUEST_TEMPLATE.md"))
    if not (root/".github"/"dependabot.yml").exists():
        findings.append(Finding("dependency-maintenance","low","No Dependabot configuration found.",".github/dependabot.yml"))
    findings.sort(key=lambda x:(-{"info":0,"low":1,"medium":2,"high":3}[x.severity],x.path or "",x.check))
    return ScanResult(str(root),base.files_scanned,findings)
