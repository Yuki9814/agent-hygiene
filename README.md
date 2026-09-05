# agent-hygiene

Fast repo hygiene checks for AI coding agents.

`agent-hygiene` scans the files that steer coding agents before they steer a
repository: `AGENTS.md`, `CLAUDE.md`, Cursor rules, Copilot instructions, MCP
JSON configs, GitHub Copilot hooks, and GitHub Actions workflows that trigger
agentic work.

It is built for one job: make agent-ready repositories safer to trust, easier
to audit, and predictable to run in CI.

## Install

`agent-hygiene` is not currently published on PyPI. Install the latest
published GitHub wheel:

```bash
python -m pip install \
  https://github.com/Yuki9814/agent-hygiene/releases/download/v0.7.0/agent_hygiene-0.7.0-py3-none-any.whl
agent-hygiene scan .
```

Or install and run a source checkout:

```bash
git clone https://github.com/Yuki9814/agent-hygiene.git
cd agent-hygiene
python -m pip install .
agent-hygiene scan .

# Without installing:
PYTHONPATH=src python -m agent_hygiene scan .
```

Published wheels and source distributions are listed on the
[GitHub Releases](https://github.com/Yuki9814/agent-hygiene/releases) page.

## Why this should exist

AI coding agents are becoming normal project infrastructure. The instruction
files and tool configs around them are now part of the supply chain, but most
repos still treat them like notes. A bad `AGENTS.md`, risky MCP command, or
overpowered issue-comment workflow can silently change how every future agent
run behaves.

`agent-hygiene` turns those surfaces into a quick health check:

- catches hidden Unicode and prompt-injection phrases in agent instructions
- flags hardcoded credentials and suspicious exfiltration patterns
- reviews MCP server commands for shells, inline code, unpinned `npx`, and
  inline secrets
- checks GitHub Copilot hook JSON for structural errors, embedded environment
  secrets, and outbound HTTP trust boundaries
- highlights risky GitHub Actions triggers such as `pull_request_target` with
  broad write permissions
- detects stale path references and missing verification commands
- emits text, JSON, Markdown, or SARIF for GitHub code scanning

## Quick start

### Collect a pinned canary observation (v0.8 source checkout)

`collect` turns a manifest-selected commit already available in a local Git
clone into a reviewable observation and an exact scanner-result digest:

```bash
agent-hygiene collect ./consenting-repository \
  --manifest ./public_canary_manifest.json \
  --repository-id example-project --output ./new-local-bundle
agent-hygiene evidence ./new-local-bundle/evidence --format markdown
```

The manifest must declare a full commit SHA and a public, revision-specific
consent link. Collection uses committed Git objects in an isolated snapshot;
uncommitted work, Git export filters, and the source clone's configuration do
not enter the scan. It makes no network requests and runs no project code.
Only the bundle's `evidence/` layer is intended for review; `private/result.json`
stays local. Collection does not verify consent or create independent reviews.
See [collection limits and workflow](docs/collection.md). Until a v0.8 wheel is
published, install the source checkout above to use this command.

### Scan a working directory

```bash
agent-hygiene scan .
agent-hygiene scan . --format json --output agent-hygiene.json
agent-hygiene scan . --format json --portable \
  --source-revision "$(git rev-parse --verify HEAD)" \
  --output agent-hygiene.json
agent-hygiene scan . --format sarif --output agent-hygiene.sarif
agent-hygiene scan . --min-score 90 --fail-on high
agent-hygiene baseline . --output .agent-hygiene-baseline.json
```

Exit codes:

- `0`: score and severity gate passed
- `1`: findings exceeded `--fail-on` or score fell below `--min-score`
- `2`: invalid usage, unreadable output, or an incomplete scan

The scanner fails closed. Symlinked, non-regular, unreadable, or oversized
agent-controlled files make the result `incomplete`; they never produce a
passing `ready` status or a successful SARIF invocation. Relevant inputs are
opened with bounded, descriptor-verified reads, so a FIFO, Unix-domain socket,
or final-component file replacement cannot be mistaken for a successfully
scanned regular file. POSIX opens also require nonblocking mode, which keeps a
special-file replacement from hanging the open; non-POSIX platforms retain
the regular-file and identity checks but do not claim the same no-hang
guarantee for platform-specific endpoints. This distinguishes a clean scan
from a scan that could not inspect all relevant inputs.

Repository configuration and baselines are treated as untrusted policy inputs:
they must be bounded regular files, remain inside the scanned repository, and
contain strict JSON. An unsafe configuration exits with code `2`; an unsafe
baseline is reported as an incomplete scan and is never used for suppression.
Evaluation and evidence inputs use the same regular-file boundary and return
exit code `2` when that boundary cannot be verified.

## GitHub Action

```yaml
name: Agent Hygiene

on:
  pull_request:
  push:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
      # Pin an existing release. Review release notes before upgrading.
      - id: hygiene
        uses: Yuki9814/agent-hygiene@v0.7.0
        with:
          min-score: "85"
          fail-on: high
          sarif: agent-hygiene.sarif
          json: agent-hygiene.json
          baseline: .agent-hygiene-baseline.json
      - uses: github/codeql-action/upload-sarif@4187e74d05793876e9989daffde9c3e66b4acd07 # v3
        if: always()
        with:
          sarif_file: agent-hygiene.sarif
      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7
        if: always()
        with:
          name: agent-hygiene-json
          path: ${{ steps.hygiene.outputs.json }}
          if-no-files-found: error
```

The optional `json` input creates a portable report before the final severity
gate runs. It omits the absolute checkout root and records the workflow commit
as a declared source revision. Download that artifact and preview it locally in
[PatchHive](https://yuki9814.github.io/PatchHive/); no scan content is sent by
PatchHive. The producer and revision fields are declarations, not a signature
or proof of authenticity. See [docs/patchhive.md](docs/patchhive.md) for the
frozen cross-project fixtures and exact handoff contract.

Treat `.agent-hygiene.json`, baselines, inline suppressions, and the workflow as
policy code: a pull request can propose changes to them. This repository's
`CODEOWNERS` marks trust-boundary files for maintainer review, but branch rules
must require that review for enforcement.

## What gets scanned

Agent instruction files:

- `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `CODEX.md`
- `.cursorrules`, `.windsurfrules`, `.clinerules`
- `.cursor/rules/*.mdc`
- `.github/copilot-instructions.md`
- `.github/instructions/*.instructions.md`
- `.github/agents/*.md`, `.claude/agents/*.md`
- `.github/prompts/*.prompt.md`
- `skills/**/SKILL.md`, `.claude/skills/**/SKILL.md`

These repository-scoped surfaces are discovered at the root and inside nested
packages, so monorepo-specific agent instructions are not silently skipped.

MCP configs:

- `.mcp.json`, `mcp.json`
- `.vscode/mcp.json`, `.cursor/mcp.json`
- `claude_desktop_config.json`

GitHub Actions:

- `.github/workflows/*.yml`
- `.github/workflows/*.yaml`

GitHub Copilot hooks:

- `.github/hooks/*.json`
- the top-level `hooks` block in `.github/copilot/settings.json` and
  `.github/copilot/settings.local.json`
- cross-tool `.claude/settings.json` and `.claude/settings.local.json` hooks

## Example finding

```text
HIGH AH006 .mcp.json:7
MCP server launches a shell with inline code.
Fix: Replace shell wrappers with a direct executable plus fixed arguments.
```

## CLI

```text
agent-hygiene scan [path]
  --format text|json|markdown|sarif
  --output FILE
  --portable
  --source-revision HEX
  --min-score NUMBER
  --fail-on none|low|medium|high|critical
  --ignore-rule RULE_ID
  --baseline FILE
  --no-baseline
  --no-color
  --quiet

agent-hygiene init [path]
agent-hygiene baseline [path] --output .agent-hygiene-baseline.json
agent-hygiene explain RULE_ID
agent-hygiene rules [--format text|json]
agent-hygiene evaluate MANIFEST [--format text|json]
agent-hygiene review-pack MANIFEST --output blind-review.json
agent-hygiene evidence DIRECTORY [--format json|markdown] [--output FILE]
```

`agent-hygiene rules --format json` emits the versioned rule catalog used by
developer tooling. It includes each rule ID, default severity, name, and
remediation guidance without requiring clients to scrape Markdown.

## Config

`agent-hygiene init` writes `.agent-hygiene.json`:

```json
{
  "exclude": [
    ".git",
    "node_modules",
    "dist",
    "build"
  ],
  "ignore": [],
  "ignore_rules": [],
  "baseline": ".agent-hygiene-baseline.json",
  "min_score": 85,
  "fail_on": "high"
}
```

`ignore` accepts glob patterns for paths, `path:line`, or
`RULE_ID:path:line`. `ignore_rules` disables entire rules. For one-off cases,
place `agent-hygiene-ignore AH006` on the same line as a finding or
`agent-hygiene-ignore-next-line AH006` on the previous line.

Existing projects can adopt the scanner without stopping every pull request on
day one:

```bash
agent-hygiene baseline . --output .agent-hygiene-baseline.json
agent-hygiene scan . --baseline .agent-hygiene-baseline.json --fail-on high
```

## Rules

| ID | Rule | Default severity |
| --- | --- | --- |
| AH001 | Hidden Unicode in agent-controlled text | high |
| AH002 | Prompt override or secrecy instruction | high |
| AH003 | Hardcoded credential-like value | critical |
| AH004 | Dangerous shell or destructive command | high |
| AH005 | Network exfiltration pattern | critical |
| AH006 | Risky MCP command shape | high |
| AH007 | Inline secret in MCP environment | critical |
| AH008 | Agentic workflow with broad trust boundary | high |
| AH009 | Missing verification command in instructions | low |
| AH010 | Stale path reference in instructions | low |
| AH011 | Vague instruction block likely to drift | medium |
| AH012 | Duplicate root instruction files can drift | low |
| AH013 | Oversized agent instruction file | medium |
| AH014 | Invalid MCP JSON | medium |
| AH015 | Risky GitHub Copilot hook | medium |

More detail lives in [docs/rules.md](docs/rules.md).

## Auditable evaluation

The repository includes a synthetic, versioned corpus with positive and
negative fixtures. The evaluator copies each fixture into an isolated temporary
repository, compares findings by rule, relative path, and line, then enforces
declared precision and recall gates:

```bash
PYTHONPATH=src python -m agent_hygiene evaluate tests/corpus/manifest.json
```

The synthetic corpus snapshot has 20 cases and 14 expected findings. It
currently reports 14 true positives, 0 false positives, and 0 false negatives against
gates of 0.95 precision and 0.90 recall. These are seeded regression fixtures,
not a claim about performance on independent real-world repositories. The
methodology and manifest contract are documented in
[docs/evaluation.md](docs/evaluation.md).

## Public evidence contract

Version 0.4 adds a separate evidence contract for future read-only canaries
against consenting public repositories. Selection manifests, machine
observations, human reviews, and adjudications remain separate, and summaries
recompute raw counts rather than trusting handwritten totals.

```bash
agent-hygiene review-pack tests/corpus/manifest.json \
  --output blind-review.json
agent-hygiene evidence evidence/v0.4.0 --format markdown
```

The review pack uses content-derived ordering and neutral case IDs, and omits
seeded labels, source fixture paths, expected findings, and scanner output.
Canary records require a canonical GitHub repository URL, fixed commit, public
consent link, and non-sensitive study limitations. Stored observations exclude
absolute checkout roots and raw finding evidence. Findings-only review cannot
measure recall, and zero denominators are reported as `null`; they also block
independent-validation status.

Current status: **0 recorded reviewers, 0 consenting public repositories,
not independently validated**. The contract and tooling are ready; the external
review and canary work in [issue #4](https://github.com/Yuki9814/agent-hygiene/issues/4)
is not complete. See [docs/evidence.md](docs/evidence.md) for the protocol.

## Performance contract

Release verification generates an ephemeral 100,000-file repository and
enforces p95 scan latency of at most 2.5 seconds and peak RSS of at most
150 MiB:

```bash
PYTHONPATH=src python tools/benchmark_large_repo.py --format json
```

Pull-request CI and release verification run the same 100,000-file gate, and
packaging depends on it. The versioned result records the platform, Python
version, fixture shape, individual timings, gates, and pass state. Fixture
generation, child startup, and imports are excluded from scan latency. See
[docs/performance.md](docs/performance.md) for the exact method and limitations.

## Machine-readable contracts

JSON scan output keeps the existing `summary` and `findings` fields and adds
`schema_version: 1` plus tool name and version metadata. Finding paths remain
repository-relative. When a GitHub repository identity or safe Git origin is
available, JSON and SARIF include the same scope fingerprint so consumers can
reconcile formats across checkout locations without encoding the absolute scan
root. SARIF remains version 2.1.0, retains
`agentHygieneFingerprint/v1`, adds GitHub code scanning's
`primaryLocationLineHash` when the bounded scan contains its complete context,
and includes the tool version, severity, and remediation properties. The
location hash keeps alerts stable when unrelated lines are inserted before a
finding and distinguishes repeated matching contexts in one file. See
[SARIF interoperability](docs/sarif.md) for the exact contract, oversized-file
behavior, and privacy boundary.

Every report also exposes a bounded `suppression_audit` summary. It counts
suppressed findings by `baseline`, `ignore-rule`, `ignore-path`, and
`inline-directive`, and includes redaction-safe details with the rule ID,
normalized repository-relative location, finding fingerprint, source, and a
static reason. Text and Markdown show the same audit, while SARIF carries it
as the custom run property `suppressionAudit`. Detail is capped at 10,000
items while the total count remains exact; raw directives, ignore patterns,
and finding evidence are never copied into the ledger. When multiple policies
match, the first applicable legacy decision wins in this order: configured
rule, configured path, baseline, then inline directive. Adding this optional
summary keeps native JSON schema version 1, rule IDs, fingerprints, and old
finding fields compatible.

Evidence is redacted before output and fingerprinting. Upgrading from an older
release can therefore change the fingerprint of a finding whose evidence
contained credential-like text; review and regenerate that baseline entry.

## Design goals

- zero runtime dependencies
- useful default checks with low setup friction
- readable output for humans, SARIF for CI
- conservative findings with practical remediation text
- no LLM API required

## Maintenance and releases

Compatibility is tested on Python 3.9 through 3.13. Releases follow semantic
versioning and publish source and wheel artifacts on GitHub. Security-sensitive
reports can be submitted privately using the process in [SECURITY.md](SECURITY.md).

Project ownership and release responsibilities are recorded in
[MAINTAINERS.md](MAINTAINERS.md). See [CONTRIBUTING.md](CONTRIBUTING.md) for
rule-change requirements, [SUPPORT.md](SUPPORT.md) for support boundaries, and
[ROADMAP.md](ROADMAP.md) for the next evidence gates.

## License

MIT
