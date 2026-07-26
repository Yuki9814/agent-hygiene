#!/usr/bin/env python3
"""Reproducible large-repository traversal benchmark."""

import argparse
import json
import math
import os
import platform
import resource
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, List

from agent_hygiene import __version__


SCHEMA_VERSION = 1
BENCHMARK_KIND = "agent-hygiene-large-repo-benchmark"
DEFAULT_FILES = 100_000
DEFAULT_WARMUPS = 2
DEFAULT_RUNS = 20
DEFAULT_MAX_P95_SECONDS = 2.5
DEFAULT_MAX_RSS_MIB = 150.0
RELEVANT_FILES = 3
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = REPOSITORY_ROOT / "src"


class BenchmarkError(RuntimeError):
    """Raised when the benchmark cannot produce a trustworthy result."""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Measure agent-hygiene traversal latency and peak RSS against a "
            "generated repository."
        )
    )
    parser.add_argument("--files", type=_bounded_files, default=DEFAULT_FILES)
    parser.add_argument("--warmups", type=_bounded_warmups, default=DEFAULT_WARMUPS)
    parser.add_argument("--runs", type=_bounded_runs, default=DEFAULT_RUNS)
    parser.add_argument(
        "--max-p95-seconds",
        type=_positive_float,
        default=DEFAULT_MAX_P95_SECONDS,
    )
    parser.add_argument(
        "--max-rss-mib",
        type=_positive_float,
        default=DEFAULT_MAX_RSS_MIB,
    )
    parser.add_argument("--format", choices=["json", "text"], default="json")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = run_benchmark(
            files=args.files,
            warmups=args.warmups,
            runs=args.runs,
            max_p95_seconds=args.max_p95_seconds,
            max_rss_mib=args.max_rss_mib,
        )
    except BenchmarkError as exc:
        print(f"agent-hygiene benchmark failed: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(render_text(result))
    return 0 if result["passed"] else 1


def run_benchmark(
    files: int,
    warmups: int,
    runs: int,
    max_p95_seconds: float,
    max_rss_mib: float,
) -> Dict[str, object]:
    root = Path(tempfile.mkdtemp(prefix="agent-hygiene-benchmark-"))
    try:
        fixture = _generate_fixture(root, files)
        samples = [
            _run_sample(root)
            for _ in range(warmups + runs)
        ][warmups:]
    except (OSError, subprocess.SubprocessError, ValueError, json.JSONDecodeError) as exc:
        raise BenchmarkError(f"{exc.__class__.__name__}: {exc}") from exc
    finally:
        try:
            shutil.rmtree(root)
        except OSError as exc:
            raise BenchmarkError(
                f"could not remove temporary fixture: {exc.__class__.__name__}"
            ) from exc

    if not samples:
        raise BenchmarkError("no measured samples were produced")
    if any(not sample["complete"] for sample in samples):
        raise BenchmarkError("a measured scan was incomplete")
    if any(sample["scanned_relevant_files"] != RELEVANT_FILES for sample in samples):
        raise BenchmarkError("the generated relevant-file contract was not scanned")

    elapsed = sorted(float(sample["seconds"]) for sample in samples)
    rss_values = [float(sample["peak_rss_mib"]) for sample in samples]
    p95 = _nearest_rank(elapsed, 0.95)
    peak_rss = max(rss_values)
    passed = p95 <= max_p95_seconds and peak_rss <= max_rss_mib

    return {
        "schema_version": SCHEMA_VERSION,
        "kind": BENCHMARK_KIND,
        "tool": {
            "name": "agent-hygiene",
            "version": __version__,
        },
        "environment": {
            "platform": platform.platform(),
            "python": platform.python_version(),
        },
        "fixture": fixture,
        "method": {
            "warmups": warmups,
            "runs": runs,
            "percentile": "nearest-rank",
            "fixture_generation_timed": False,
            "child_startup_included": False,
        },
        "metrics": {
            "seconds": elapsed,
            "p50_seconds": statistics.median(elapsed),
            "p95_seconds": p95,
            "peak_rss_mib": peak_rss,
            "scanned_relevant_files": RELEVANT_FILES,
        },
        "gates": {
            "max_p95_seconds": max_p95_seconds,
            "max_peak_rss_mib": max_rss_mib,
        },
        "passed": passed,
    }


def render_text(result: Dict[str, object]) -> str:
    fixture = result["fixture"]
    metrics = result["metrics"]
    gates = result["gates"]
    status = "pass" if result["passed"] else "fail"
    return "\n".join(
        [
            f"agent-hygiene 100k benchmark: {status}",
            (
                f"files={fixture['total_files']}, "
                f"relevant={metrics['scanned_relevant_files']}"
            ),
            (
                f"p95={metrics['p95_seconds']:.3f}s "
                f"(gate {gates['max_p95_seconds']:.3f}s)"
            ),
            (
                f"peak RSS={metrics['peak_rss_mib']:.2f} MiB "
                f"(gate {gates['max_peak_rss_mib']:.2f} MiB)"
            ),
        ]
    )


def _generate_fixture(root: Path, total_files: int) -> Dict[str, object]:
    started = time.perf_counter()
    noise_files = total_files - RELEVANT_FILES
    directory_count = min(100, max(1, math.ceil(max(noise_files, 1) / 1000)))
    directories = []
    for index in range(directory_count):
        directory = root / "noise" / f"group-{index:03d}"
        directory.mkdir(parents=True)
        directories.append(directory)

    for index in range(noise_files):
        path = directories[index % directory_count] / f"file-{index:06d}.txt"
        path.touch()

    (root / "AGENTS.md").write_text(
        "Run `python -m unittest` before accepting changes.\n",
        encoding="utf-8",
    )
    (root / ".mcp.json").write_text(
        '{"mcpServers": {}}\n',
        encoding="utf-8",
    )
    workflows = root / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(
        "on: push\npermissions:\n  contents: read\n",
        encoding="utf-8",
    )

    actual_files = sum(len(names) for _, _, names in os.walk(root))
    if actual_files != total_files:
        raise BenchmarkError(
            f"fixture contains {actual_files} files instead of {total_files}"
        )
    return {
        "total_files": total_files,
        "noise_files": noise_files,
        "relevant_files": RELEVANT_FILES,
        "noise_directories": directory_count,
        "generation_seconds": time.perf_counter() - started,
    }


def _run_sample(root: Path) -> Dict[str, object]:
    source = """
import json
import platform
import resource
import sys
import time
from pathlib import Path

from agent_hygiene.config import Config
from agent_hygiene.scanner import scan

started = time.perf_counter()
result = scan(
    Path(sys.argv[1]),
    Config(baseline=None, min_score=0, fail_on="none"),
    use_baseline=False,
)
seconds = time.perf_counter() - started
peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
peak_rss_mib = peak / (1024 * 1024) if platform.system() == "Darwin" else peak / 1024
print(json.dumps({
    "seconds": seconds,
    "peak_rss_mib": peak_rss_mib,
    "scanned_relevant_files": result.summary.scanned_files,
    "complete": result.summary.complete,
}))
"""
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONPATH"] = str(SOURCE_ROOT)
    process = subprocess.run(
        [sys.executable, "-B", "-c", source, str(root)],
        cwd=REPOSITORY_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    if process.returncode != 0:
        stderr = process.stderr.strip().splitlines()
        detail = stderr[-1] if stderr else f"exit {process.returncode}"
        raise BenchmarkError(f"sample process failed: {detail}")
    payload = json.loads(process.stdout)
    if not isinstance(payload, dict):
        raise BenchmarkError("sample output must be a JSON object")
    return payload


def _nearest_rank(values: List[float], percentile: float) -> float:
    if not values:
        raise BenchmarkError("cannot calculate a percentile without samples")
    index = math.ceil(percentile * len(values)) - 1
    return values[max(0, index)]


def _bounded_files(value: str) -> int:
    return _bounded_int(value, "files", RELEVANT_FILES, 1_000_000)


def _bounded_warmups(value: str) -> int:
    return _bounded_int(value, "warmups", 0, 20)


def _bounded_runs(value: str) -> int:
    return _bounded_int(value, "runs", 1, 50)


def _bounded_int(value: str, label: str, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{label} must be an integer") from exc
    if not minimum <= parsed <= maximum:
        raise argparse.ArgumentTypeError(
            f"{label} must be from {minimum} to {maximum}"
        )
    return parsed


def _positive_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a positive number") from exc
    if not math.isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError("must be a positive number")
    return parsed


if __name__ == "__main__":
    raise SystemExit(main())
