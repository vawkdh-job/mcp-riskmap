from __future__ import annotations

import argparse
import sys
from pathlib import Path

from mcp_riskmap import __version__
from mcp_riskmap.baseline import (
    BaselineError,
    audit_baseline,
    filter_baselined_findings,
    load_baseline,
    render_baseline,
    render_baseline_audit,
)
from mcp_riskmap.models import SEVERITY_ORDER, ScanResult
from mcp_riskmap.profiles import PROFILE_FAIL_ON, fail_threshold
from mcp_riskmap.reporters.json_reporter import render_json
from mcp_riskmap.reporters.markdown import render_markdown
from mcp_riskmap.reporters.sarif import render_sarif
from mcp_riskmap.reporters.table import render_table
from mcp_riskmap.scanner import ScanInputError, scan_path


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.version:
        print(f"mcp-riskmap {__version__}")
        return 0
    if args.command == "scan":
        return _scan(args)
    if args.command == "baseline":
        return _baseline(args)
    if args.command == "baseline-check":
        return _baseline_check(args)
    parser.print_help()
    return 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-riskmap",
        description="Static MCP and agent-tool repository risk scanner.",
    )
    parser.add_argument("--version", action="store_true", help="Print the package version and exit.")
    subparsers = parser.add_subparsers(dest="command")
    scan = subparsers.add_parser("scan", help="Scan a repository or directory.")
    scan.add_argument("path", nargs="?", default=".", help="Path to scan.")
    scan.add_argument(
        "--profile",
        choices=list(PROFILE_FAIL_ON),
        default="local",
        help="Apply a default fail policy for local, audit, ci, or release use.",
    )
    scan.add_argument(
        "--format",
        choices=["table", "json", "markdown", "sarif"],
        default="table",
        help="Output format.",
    )
    scan.add_argument("--output", help="Write report to a file instead of stdout.")
    scan.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="Exclude a relative path glob from scanning. Can be passed more than once.",
    )
    scan.add_argument(
        "--fail-on",
        choices=list(SEVERITY_ORDER),
        help="Override the profile and return exit code 1 when any finding is at or above this severity.",
    )
    scan.add_argument("--baseline", help="Filter findings already recorded in a baseline JSON file.")

    baseline = subparsers.add_parser("baseline", help="Create a baseline JSON file from current findings.")
    baseline.add_argument("path", nargs="?", default=".", help="Path to scan when creating the baseline.")
    baseline.add_argument("--output", required=True, help="Write the baseline JSON file.")
    baseline.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="Exclude a relative path glob from baseline scanning. Can be passed more than once.",
    )

    baseline_check = subparsers.add_parser(
        "baseline-check",
        help="Compare current findings with a baseline and report active, stale, and new findings.",
    )
    baseline_check.add_argument("path", nargs="?", default=".", help="Path to scan when checking the baseline.")
    baseline_check.add_argument("--baseline", required=True, help="Baseline JSON file to compare against.")
    baseline_check.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format.",
    )
    baseline_check.add_argument("--output", help="Write report to a file instead of stdout.")
    baseline_check.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="Exclude a relative path glob from baseline checking. Can be passed more than once.",
    )
    return parser


def _scan(args: argparse.Namespace) -> int:
    try:
        result = scan_path(args.path, exclude_patterns=args.exclude)
    except ScanInputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.baseline:
        try:
            result = filter_baselined_findings(result, load_baseline(args.baseline))
        except BaselineError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    rendered = render_result(result, args.format)
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)

    threshold = fail_threshold(args.profile, args.fail_on)
    if threshold and result.count_at_or_above(threshold):
        return 1
    return 0


def _baseline(args: argparse.Namespace) -> int:
    try:
        result = scan_path(args.path, exclude_patterns=args.exclude)
    except ScanInputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    Path(args.output).write_text(render_baseline(result) + "\n", encoding="utf-8")
    print(f"Wrote baseline with {len(result.findings)} findings: {args.output}")
    return 0


def _baseline_check(args: argparse.Namespace) -> int:
    try:
        result = scan_path(args.path, exclude_patterns=args.exclude)
        audit = audit_baseline(result, load_baseline(args.baseline))
    except ScanInputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except BaselineError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    rendered = render_baseline_audit(audit, args.format)
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)

    if audit.new_findings:
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
