from __future__ import annotations

import argparse
import sys
from pathlib import Path

from mcp_riskmap import __version__
from mcp_riskmap.models import SEVERITY_ORDER, ScanResult
from mcp_riskmap.reporters.json_reporter import render_json
from mcp_riskmap.reporters.markdown import render_markdown
from mcp_riskmap.reporters.sarif import render_sarif
from mcp_riskmap.reporters.table import render_table
from mcp_riskmap.scanner import ScanInputError, scan_path


def main(argv: list[str] | None = None) -> int:
    if argv == ["--version"]:
        print(f"mcp-riskmap {__version__}")
        return 0

    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return _scan(args)
    parser.print_help()
    return 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-riskmap",
        description="Static MCP and agent-tool repository risk scanner.",
    )
    subparsers = parser.add_subparsers(dest="command")
    scan = subparsers.add_parser("scan", help="Scan a repository or directory.")
    scan.add_argument("path", nargs="?", default=".", help="Path to scan.")
    scan.add_argument(
        "--format",
        choices=["table", "json", "markdown", "sarif"],
        default="table",
        help="Output format.",
    )
    scan.add_argument("--output", help="Write report to a file instead of stdout.")
    scan.add_argument(
        "--fail-on",
        choices=list(SEVERITY_ORDER),
        help="Return exit code 1 when any finding is at or above this severity.",
    )
    return parser


def _scan(args: argparse.Namespace) -> int:
    try:
        result = scan_path(args.path)
    except ScanInputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    rendered = render_result(result, args.format)
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)

    if args.fail_on and result.count_at_or_above(args.fail_on):
        return 1
    return 0


def render_result(result: ScanResult, report_format: str) -> str:
    if report_format == "json":
        return render_json(result)
    if report_format == "markdown":
        return render_markdown(result)
    if report_format == "sarif":
        return render_sarif(result)
    return render_table(result)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
