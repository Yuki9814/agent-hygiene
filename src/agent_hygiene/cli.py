import argparse
from dataclasses import replace
import json
import re
import sys
from pathlib import Path

from . import __version__
from .baseline import render_baseline
from .config import ConfigError, default_config_text, load_config
from .evidence import (
    EvidenceError,
    build_review_pack,
    load_evidence_directory,
    render_evidence_json,
    render_evidence_markdown,
)
from .evaluation import EvaluationError, evaluate_manifest, render_evaluation
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
    if args.command == "evaluate":
        return run_evaluate(args)
    if args.command == "review-pack":
        return run_review_pack(args)
    if args.command == "evidence":
        return run_evidence(args)

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
    scan_parser.add_argument(
        "--min-score",
        type=_score_argument,
        help="minimum passing score from 0 to 100",
    )
    scan_parser.add_argument("--fail-on", choices=["none", "low", "medium", "high", "critical"], help="lowest failing severity")
    scan_parser.add_argument("--ignore-rule", action="append", default=[], help="ignore a rule id for this run")
    scan_parser.add_argument("--baseline", help="baseline file to suppress existing findings")
    scan_parser.add_argument("--no-baseline", action="store_true", help="do not apply a configured baseline")
    scan_parser.add_argument("--quiet", action="store_true", help="only print output when findings exist")
    scan_parser.add_argument("--no-color", action="store_true", help="reserved for stable CI output")
    scan_parser.add_argument(
        "--portable",
        action="store_true",
        help="omit the absolute scan root from JSON output",
    )
    scan_parser.add_argument(
        "--source-revision",
        type=_source_revision_argument,
        help="declare the scanned source revision as 7 to 64 hexadecimal characters",
    )

    init_parser = subparsers.add_parser("init", help="write .agent-hygiene.json")
    init_parser.add_argument("path", nargs="?", default=".", help="repository path")

    baseline_parser = subparsers.add_parser("baseline", help="write a baseline for current findings")
    baseline_parser.add_argument("path", nargs="?", default=".", help="repository path")
    baseline_parser.add_argument("--output", default=".agent-hygiene-baseline.json", help="baseline output path")

    explain_parser = subparsers.add_parser("explain", help="explain a rule")
    explain_parser.add_argument("rule_id", help="rule id such as AH006")

    evaluate_parser = subparsers.add_parser(
        "evaluate",
        help="measure precision and recall against a synthetic corpus",
    )
    evaluate_parser.add_argument("manifest", help="path to a version 1 corpus manifest")
    evaluate_parser.add_argument("--format", choices=["text", "json"], default="text")
    evaluate_parser.add_argument("--min-precision", type=float, help="override manifest precision gate")
    evaluate_parser.add_argument("--min-recall", type=float, help="override manifest recall gate")

    review_pack_parser = subparsers.add_parser(
        "review-pack",
        help="build a neutral blind-review pack from a corpus manifest",
    )
    review_pack_parser.add_argument("manifest", help="path to a version 1 corpus manifest")
    review_pack_parser.add_argument(
        "--output",
        required=True,
        help="write the review pack to this JSON file",
    )

    evidence_parser = subparsers.add_parser(
        "evidence",
        help="validate and summarize a layered public-canary evidence directory",
    )
    evidence_parser.add_argument("directory", help="path to the evidence directory")
    evidence_parser.add_argument(
        "--format",
        choices=["json", "markdown"],
        default="json",
    )
    evidence_parser.add_argument("--output", help="write the summary to a file")

    return parser


def run_scan(args: argparse.Namespace) -> int:
    if args.portable and args.format != "json":
        print(
            "agent-hygiene: --portable requires --format json",
            file=sys.stderr,
        )
        return 2

    root = Path(args.path).resolve()
    if not root.exists() or not root.is_dir():
        print(f"agent-hygiene: path is not a directory: {root}", file=sys.stderr)
        return 2

    try:
        config = load_config(root)
    except ConfigError as exc:
        print(f"agent-hygiene: invalid configuration: {exc}", file=sys.stderr)
        return 2
    min_score = args.min_score if args.min_score is not None else config.min_score
    fail_on = args.fail_on if args.fail_on is not None else config.fail_on
    config = replace(
        config,
        ignore_rules=list(config.ignore_rules) + [rule.upper() for rule in args.ignore_rule],
        baseline=args.baseline if args.baseline else config.baseline,
    )

    result = scan(root, config, use_baseline=not args.no_baseline)
    if args.source_revision:
        result = replace(
            result,
            summary=replace(
                result.summary,
                source_revision=args.source_revision,
            ),
        )
    text = render(result, args.format, portable=args.portable)

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

    if not result.summary.complete:
        return 2
    return 1 if should_fail(result, min_score, fail_on) else 0


def run_init(args: argparse.Namespace) -> int:
    root = Path(args.path).resolve()
    if not root.exists() or not root.is_dir():
        print(f"agent-hygiene: path is not a directory: {root}", file=sys.stderr)
        return 2
    config_path = root / ".agent-hygiene.json"
    if config_path.is_symlink():
        print("agent-hygiene: refusing to replace a symlinked configuration", file=sys.stderr)
        return 2
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
    try:
        config = load_config(root)
    except ConfigError as exc:
        print(f"agent-hygiene: invalid configuration: {exc}", file=sys.stderr)
        return 2
    result = scan(root, config, use_baseline=False)
    if not result.summary.complete:
        print("agent-hygiene: refusing to create a baseline from an incomplete scan", file=sys.stderr)
        return 2
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


def run_evaluate(args: argparse.Namespace) -> int:
    try:
        result = evaluate_manifest(
            Path(args.manifest),
            min_precision=args.min_precision,
            min_recall=args.min_recall,
        )
    except EvaluationError as exc:
        print(f"agent-hygiene: evaluation failed: {exc}", file=sys.stderr)
        return 2
    print(render_evaluation(result, args.format), end="")
    return 0 if result.passed else 1


def run_review_pack(args: argparse.Namespace) -> int:
    try:
        pack = build_review_pack(Path(args.manifest))
        text = json.dumps(pack, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        write_output(text, args.output)
    except EvidenceError as exc:
        print(f"agent-hygiene: review pack failed: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(
            f"agent-hygiene: could not write {args.output}: "
            f"{exc.__class__.__name__}",
            file=sys.stderr,
        )
        return 2
    print(f"wrote {args.output} with {len(pack['cases'])} cases")
    return 0


def run_evidence(args: argparse.Namespace) -> int:
    try:
        summary = load_evidence_directory(Path(args.directory))
        text = (
            render_evidence_markdown(summary)
            if args.format == "markdown"
            else render_evidence_json(summary)
        )
        if args.output:
            write_output(text, args.output)
    except EvidenceError as exc:
        print(f"agent-hygiene: evidence validation failed: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        destination = args.output or "standard output"
        print(
            f"agent-hygiene: could not write {destination}: "
            f"{exc.__class__.__name__}",
            file=sys.stderr,
        )
        return 2

    if args.output:
        print(f"wrote {args.output}")
    else:
        print(text, end="")
    return 0


def severity_at_least(left: str, right: str) -> bool:
    return SEVERITY_ORDER[left] >= SEVERITY_ORDER[right]


def _score_argument(value: str) -> int:
    try:
        score = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer from 0 to 100") from exc
    if not 0 <= score <= 100:
        raise argparse.ArgumentTypeError("must be an integer from 0 to 100")
    return score


def _source_revision_argument(value: str) -> str:
    if not re.fullmatch(r"[0-9a-fA-F]{7,64}", value):
        raise argparse.ArgumentTypeError(
            "must contain 7 to 64 hexadecimal characters"
        )
    return value.lower()
