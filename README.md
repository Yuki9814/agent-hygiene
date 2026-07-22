# agent-hygiene

Fast repo hygiene checks for AI coding agents.

`agent-hygiene` scans the files that steer coding agents before they steer a
repository: `AGENTS.md`, `CLAUDE.md`, Cursor rules, Copilot instructions, MCP
JSON configs, and GitHub Actions workflows that trigger agentic work.

It is built for one job: make agent-ready repositories safer to trust, easier
to audit, and boring to run in CI.

```bash
python -m pip install agent-hygiene
agent-hygiene scan .
```

For this source checkout:

```bash
PYTHONPATH=src python -m agent_hygiene scan .
```

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
- highlights risky GitHub Actions triggers such as `pull_request_target` with
  broad write permissions
- detects stale path references and missing verification commands
- emits text, JSON, Markdown, or SARIF for GitHub code scanning

## Quick start

```bash
agent-hygiene scan .
agent-hygiene scan . --format json --output agent-hygiene.json
agent-hygiene scan . --format sarif --output agent-hygiene.sarif
agent-hygiene scan . --min-score 90 --fail-on high
agent-hygiene baseline . --output .agent-hygiene-baseline.json
```

Exit codes:

- `0`: score and severity gate passed
- `1`: findings exceeded `--fail-on` or score fell below `--min-score`
- `2`: invalid usage, unreadable output, or an incomplete scan

The scanner fails closed. Symlinked, unreadable, or oversized agent-controlled
files make the result `incomplete`; they never produce a passing `ready` status
or a successful SARIF invocation. This distinguishes a clean scan from a scan
that could not inspect all relevant inputs.

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
      - uses: actions/checkout@v4
      - uses: Yuki9814/agent-hygiene@v0
        with:
          min-score: "85"
          fail-on: high
          sarif: agent-hygiene.sarif
          baseline: .agent-hygiene-baseline.json
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: agent-hygiene.sarif
```

## What gets scanned

Agent instruction files:

- `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `CODEX.md`
- `.cursorrules`, `.windsurfrules`, `.clinerules`
- `.cursor/rules/*.mdc`
- `.github/copilot-instructions.md`
- `.github/instructions/*.instructions.md`
- `skills/**/SKILL.md`, `.claude/skills/**/SKILL.md`

MCP configs:

- `.mcp.json`, `mcp.json`
- `.vscode/mcp.json`, `.cursor/mcp.json`
- `claude_desktop_config.json`

GitHub Actions:

- `.github/workflows/*.yml`
- `.github/workflows/*.yaml`

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
```

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

More detail lives in [docs/rules.md](docs/rules.md).

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

## Roadmap

- repository-specific rule packs
- autofix for stale paths and generated instruction headers
- reusable score badge endpoint

## License

MIT
