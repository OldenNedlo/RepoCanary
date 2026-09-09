from __future__ import annotations
import argparse
from pathlib import Path
import sys
from .config import load_policy
from .release import release_check
from .scanner import ScanResult,scan_repository,should_fail

def _add_common(parser):
    parser.add_argument("path",nargs="?",default=".")
    parser.add_argument("--config",dest="config_path")
    parser.add_argument("--json",dest="json_path")
    parser.add_argument("--markdown",dest="markdown_path")
    parser.add_argument("--sarif",dest="sarif_path")
    parser.add_argument("--fail-on",choices=["never","low","medium","high"])
    parser.add_argument("--large-file-mib",type=int)

def parser():
    root=argparse.ArgumentParser(prog="repocanary",description="Local-first repository health and release-readiness scanner.")
    sub=root.add_subparsers(dest="command",required=True)
    scan=sub.add_parser("scan",help="Scan repository hygiene and maintenance signals.")
    _add_common(scan)
    release=sub.add_parser("release-check",help="Run scan plus release-readiness checks.")
    _add_common(release)
    return root

def _print(result:ScanResult):
    print("RepoCanary repository scan")
    print(f"Repository: {result.repository}")
    print(f"Files scanned: {result.files_scanned}")
    print(f"Findings: {len(result.findings)}")
    print()
    if not result.findings: print("No findings.")
    for item in result.findings:
        loc=item.path or ""
        if item.line is not None: loc+=f":{item.line}"
        print(f"[{item.severity.upper()}] {item.check} {loc}: {item.message}")

def main(argv=None):
    args=parser().parse_args(argv)
    root=Path(args.path).resolve()
    try:
        policy=load_policy(root,args.config_path)
        large=args.large_file_mib or policy.large_file_mib
        fail_on=args.fail_on or policy.fail_on
        result=release_check(root,large,policy.ignore) if args.command=="release-check" else scan_repository(root,large,policy.ignore)
    except (ValueError,OSError) as exc:
        print(f"error: {exc}",file=sys.stderr); return 2
    _print(result)
    if args.json_path: Path(args.json_path).write_text(result.to_json()+"\n",encoding="utf-8")
    if args.markdown_path: Path(args.markdown_path).write_text(result.to_markdown(),encoding="utf-8")
    if args.sarif_path: Path(args.sarif_path).write_text(result.to_sarif()+"\n",encoding="utf-8")
    return 1 if should_fail(result,fail_on) else 0

if __name__=="__main__": raise SystemExit(main())
