import argparse
from dataclasses import replace
import sys
from pathlib import Path

from . import __version__
from .baseline import render_baseline
from .config import default_config_text, load_config
from .models import SEVERITY_ORDER
from .reporters import render, should_fail, write_output
from .rules import RULES
from .scanner import scan


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return run_scan(args)
    if args.command == "init":
        return run_init(args)
    if args.command == "baseline":
        return run_baseline(args)
    if args.command == "explain":
        return run_explain(args)

    parser.print_help()
    return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-hygiene",
        description="Scan AI agent instruction files, MCP configs, and agentic workflows.",
    )
    parser.add_argument("--version", action="version", version=f"agent-hygiene {__version__}")
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="scan a repository")
    scan_parser.add_argument("path", nargs="?", default=".", help="repository path to scan")
    scan_parser.add_argument("--format", choices=["text", "json", "markdown", "sarif"], default="text")
    scan_parser.add_argument("--output", help="write report to a file")
    scan_parser.add_argument("--min-score", type=int, help="minimum passing score")
    scan_parser.add_argument("--fail-on", choices=["none", "low", "medium", "high", "critical"], help="lowest failing severity")
    scan_parser.add_argument("--ignore-rule", action="append", default=[], help="ignore a rule id for this run")
    scan_parser.add_argument("--baseline", help="baseline file to suppress existing findings")
    scan_parser.add_argument("--no-baseline", action="store_true", help="do not apply a configured baseline")
    scan_parser.add_argument("--quiet", action="store_true", help="only print output when findings exist")
    scan_parser.add_argument("--no-color", action="store_true", help="reserved for stable CI output")

    init_parser = subparsers.add_parser("init", help="write .agent-hygiene.json")
    init_parser.add_argument("path", nargs="?", default=".", help="repository path")

    baseline_parser = subparsers.add_parser("baseline", help="write a baseline for current findings")
    baseline_parser.add_argument("path", nargs="?", default=".", help="repository path")
    baseline_parser.add_argument("--output", default=".agent-hygiene-baseline.json", help="baseline output path")

    explain_parser = subparsers.add_parser("explain", help="explain a rule")
    explain_parser.add_argument("rule_id", help="rule id such as AH006")

    return parser


def run_scan(args: argparse.Namespace) -> int:
    root = Path(args.path).resolve()
    if not root.exists() or not root.is_dir():
        print(f"agent-hygiene: path is not a directory: {root}", file=sys.stderr)
        return 2

    config = load_config(root)
    min_score = args.min_score if args.min_score is not None else config.min_score
    fail_on = args.fail_on if args.fail_on is not None else config.fail_on
    config = replace(
        config,
        ignore_rules=list(config.ignore_rules) + [rule.upper() for rule in args.ignore_rule],
        baseline=args.baseline if args.baseline else config.baseline,
    )

    result = scan(root, config, use_baseline=not args.no_baseline)
    text = render(result, args.format)

    if args.output:
        try:
            write_output(text, args.output)
        except OSError as exc:
            print(f"agent-hygiene: could not write {args.output}: {exc}", file=sys.stderr)
            return 2
        if not args.quiet:
            print(f"wrote {args.output}")
    elif not args.quiet or result.findings:
        print(text, end="")

    return 1 if should_fail(result, min_score, fail_on) else 0


def run_init(args: argparse.Namespace) -> int:
    root = Path(args.path).resolve()
    if not root.exists() or not root.is_dir():
        print(f"agent-hygiene: path is not a directory: {root}", file=sys.stderr)
        return 2
    config_path = root / ".agent-hygiene.json"
    if config_path.exists():
        print(f"exists {config_path}")
        return 0
    config_path.write_text(default_config_text(), encoding="utf-8")
    print(f"wrote {config_path}")
    return 0


def run_baseline(args: argparse.Namespace) -> int:
    root = Path(args.path).resolve()
    if not root.exists() or not root.is_dir():
        print(f"agent-hygiene: path is not a directory: {root}", file=sys.stderr)
        return 2
    config = load_config(root)
    result = scan(root, config, use_baseline=False)
    text = render_baseline(result.findings)
    try:
        write_output(text, args.output)
    except OSError as exc:
        print(f"agent-hygiene: could not write {args.output}: {exc}", file=sys.stderr)
        return 2
    print(f"wrote {args.output} with {len(result.findings)} findings")
    return 0


def run_explain(args: argparse.Namespace) -> int:
    rule_id = args.rule_id.upper()
    meta = RULES.get(rule_id)
    if meta is None:
        print(f"unknown rule {args.rule_id}", file=sys.stderr)
        return 2
    print(f"{rule_id}: {meta['name']}")
    print(f"severity: {meta['severity']}")
    print(meta["help"])
    return 0


def severity_at_least(left: str, right: str) -> bool:
    return SEVERITY_ORDER[left] >= SEVERITY_ORDER[right]
