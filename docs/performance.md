# Performance contract

The large-repository benchmark measures traversal overhead without treating a
fast scan as evidence of rule accuracy or project adoption.

## Reproduce the gate

From a source checkout with Python 3.13:

```bash
PYTHONPATH=src python tools/benchmark_large_repo.py --format json
```

The benchmark creates an ephemeral repository containing exactly 100,000 files:
99,997 unrelated text files distributed across 100 directories plus one
`AGENTS.md`, one `.mcp.json`, and one GitHub Actions workflow. Fixture creation
and deletion are outside the timed region.

Two child-process runs warm the filesystem and interpreter path. Twenty
additional child processes are measured. Scan timing starts after child-process
startup and imports; peak RSS remains the maximum whole-process high-water mark.
The reported p95 uses the nearest-rank method, so with 20 measurements one
isolated slowest sample does not define the percentile. Linux reports
`ru_maxrss` in KiB; macOS reports bytes; the benchmark normalizes both to MiB.

The version 1 JSON result records the environment, fixture shape, individual
timings, method, gates, and pass state. It never includes the temporary absolute
path.

## Gates

- p95 scan latency: at most 2.5 seconds
- peak RSS: at most 150 MiB
- scan completeness: required
- discovered relevant files: exactly 3

Release verification and pull-request CI enforce the same gates on Python 3.13,
and package verification depends on the result. This prevents a version tag
from being the first place that the hosted-runner release contract is tested.

The immutable `v0.4.0` tag recorded p95 3.884 seconds and peak RSS 19.38 MiB on
GitHub's Ubuntu x64 runner. No release was created because that run exceeded the
2.5-second latency gate. Version 0.4.1 removes the duplicate repository walk and
avoids constructing paths for irrelevant files instead of weakening the gate.

The fixture primarily measures the cost of walking a large repository with a
small number of agent-control surfaces. It does not model a repository
containing 100,000 relevant instruction or configuration files, network
filesystems, or cold storage.

Hosted-runner results can vary. Gate changes require a recorded benchmark
result, an explanation of the environment and fixture, and maintainer review;
the limits must not be raised merely to make a transient failure disappear.
