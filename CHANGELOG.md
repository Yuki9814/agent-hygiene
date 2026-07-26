# Changelog

All notable changes are documented here. This project follows semantic versioning.

## 0.4.1 - 2026-07-26

- Collapse discovery and symlink auditing into one deterministic, pruned
  traversal, and avoid per-file path construction for irrelevant files.
- Enforce the full 100,000-file release performance contract in pull requests
  so an immutable version tag is not the first exact hosted-runner gate.
- Keep the 2.5-second/150-MiB contract unchanged. The immutable `v0.4.0` tag
  exceeded the GitHub Ubuntu x64 latency gate at p95 3.884 seconds, so its
  workflow correctly created no release.
- Declare 0.4.x as the supported line while retaining time-bounded critical-fix
  support for 0.3.x and 0.2.x.

## 0.4.0 - 2026-07-26

- Add a strict, versioned evidence contract for consenting public-repository
  canaries, with separate manifests, machine observations, human reviews, and
  adjudications.
- Add deterministic blind-review packs with content-derived ordering that omit
  seeded labels, source fixture paths, expected findings, and scanner output.
- Add JSON and Markdown canary summaries with per-rule raw counts. Zero
  denominators and findings-only reviews never claim perfect precision or
  measured recall.
- Keep scan and synthetic-evaluation JSON contracts unchanged. Synthetic corpus
  gates remain separate from canary observations.
- Stream repository discovery instead of materializing every path before
  scanning.
- Add a reproducible 100,000-file benchmark. Release verification enforces p95
  scan latency of at most 2.5 seconds and peak RSS of at most 150 MiB; pull
  requests retain a broad functional guardrail to avoid hosted-runner noise.
- Reject duplicate canonical repository identities, sensitive limitations, and
  malformed or non-canonical URLs before evidence can receive independent
  validation status.
- Publish the evidence and performance methodology without claiming external
  validation. At release preparation time there are 0 recorded reviewers,
  0 consenting repositories, and no independently validated canary result.

## 0.3.0 - 2026-07-26

- Add a versioned synthetic corpus and `evaluate` command with explicit
  precision and recall gates.
- Add JSON schema/tool metadata and SARIF tool, severity, and remediation
  metadata without removing existing fields.
- Validate GitHub Action inputs outside shell code, including score, severity,
  workspace path, baseline, and SARIF boundaries.
- Isolate Action Python startup from consumer modules, split release
  verification from the write-token job, and pin every workflow dependency.
- Detect relevant symlinked directories; safely bound and strictly parse agent
  files, configuration, baselines, MCP JSON, and evaluation manifests.
- Redact credential-like evidence before fingerprinting or rendering, and
  escape control characters in human-readable reports.
- Security-sensitive findings can receive a new fingerprint after redaction;
  review and regenerate affected baselines rather than copying old secrets.
- Fix `.env` exfiltration matching and a workflow write-permission false
  positive.
- Expand security, output-contract, suppression, baseline, evaluation, and
  Action regression coverage.
- Document truthful GitHub installation, maintenance ownership, support,
  release, security, and roadmap policies.

## 0.2.0 - 2026-07-22

- Fail closed when relevant files are symlinked, unreadable, or oversized.
- Report discovery issues in text, Markdown, JSON, and SARIF output.
- Mark incomplete SARIF invocations as unsuccessful.
- Use stable hashed SARIF partial fingerprints without exposing evidence text.
- Include line locations in baseline fingerprints to prevent collisions.
- Expand CI coverage through Python 3.13 and verify distribution builds.

## 0.1.0 - 2026-05-31

- Initial deterministic scanner, CLI, GitHub Action, baselines, and SARIF output.
