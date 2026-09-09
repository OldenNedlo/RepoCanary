from __future__ import annotations

import argparse
from pathlib import Path
import sys

from .scanner import scan_repository, should_fail


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="repocanary", description="Local-first repository health scanner.")
    sub = root.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan")
    scan.add_argument("path", nargs="?", default=".")
    scan.add_argument("--json", dest="json_path")
    scan.add_argument("--markdown", dest="markdown_path")
    scan.add_argument("--fail-on", choices=["never", "low", "medium", "high"], default="never")
    scan.add_argument("--large-file-mib", type=int, default=10)
    return root


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    try:
        result = scan_repository(args.path, args.large_file_mib)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print("RepoCanary repository scan")
    print(f"Repository: {result.repository}")
    print(f"Files scanned: {result.files_scanned}")
    print(f"Findings: {len(result.findings)}")
    for item in result.findings:
        loc = item.path or ""
        if item.line is not None:
            loc += f":{item.line}"
        print(f"[{item.severity.upper()}] {item.check} {loc}: {item.message}")

    if args.json_path:
        Path(args.json_path).write_text(result.to_json() + "\n", encoding="utf-8")
    if args.markdown_path:
        Path(args.markdown_path).write_text(result.to_markdown(), encoding="utf-8")
    return 1 if should_fail(result, args.fail_on) else 0


if __name__ == "__main__":
    raise SystemExit(main())
