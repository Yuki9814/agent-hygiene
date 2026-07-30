# Changelog

All notable changes are documented here. This project follows semantic versioning.

## 0.6.0 - 2026-07-30

- Scan GitHub prompt files and Claude-compatible agent profiles alongside
  existing Copilot custom agents, repository instructions, and skills.
- Discover supported Copilot instructions, agent profiles, prompt files,
  Claude agents, and Cursor rules inside nested monorepo packages instead of
  limiting those surfaces to the repository root.
- Regenerate the deterministic PatchHive interoperability reports and
  published SHA-256 digests with v0.6.0 producer metadata.
- Keep the single deterministic repository walk, bounded regular-file reads,
  existing rule IDs, output schemas, and zero-dependency runtime unchanged.

## 0.5.2 - 2026-07-29

- Read scanner inputs, configuration, baselines, evaluation manifests and
  fixtures, evidence documents, and review fixtures through one bounded
  regular-file primitive.
- Reject FIFOs, Unix-domain sockets, symlinks, and final-component file
  replacements before reading. POSIX opens require nonblocking mode so a
  special-file replacement cannot hang a scan or validation command.
- Preserve existing rule IDs, finding fingerprints, JSON/SARIF contracts,
  oversized-prefix behavior, UTF-8 handling, and zero runtime dependencies.

## 0.5.1 - 2026-07-28

- Add GitHub-compatible SARIF `primaryLocationLineHash` values while retaining
  `agentHygieneFingerprint/v1`, JSON schema 1, baseline version 2, stable rule
  IDs, and the existing finding-fingerprint algorithm.
- Normalize CR, LF, and CRLF, hash UTF-16 code units, ignore ASCII spaces and
  tabs, and disambiguate repeated hashes using the same `:N` suffix convention
  as the CodeQL Action uploader.
- Keep CR/LF line locations aligned across rules, suppressions, JSON errors,
  and SARIF. On an oversized file, emit a location hash only when its complete
  100-unit context is inside the bounded scan prefix; the invocation remains
  unsuccessful.
- Correcting line semantics can change the line and existing finding
  fingerprint for files that used VT, FF, NEL, LINE SEPARATOR, or PARAGRAPH
  SEPARATOR as a line break. Review and regenerate those narrow baseline
  entries after upgrading.

## 0.5.0 - 2026-07-27

- Add an optional GitHub Action `json` input and output so a protected CI run
  can produce a native report for local maintainer handoff before the final
  severity gate.
- Add `--portable` JSON output, which omits the absolute checkout root, and
  `--source-revision`, which carries a bounded declared revision into native
  JSON and SARIF.
- Reject Action output collisions with the baseline or another report before
  scanning, while keeping all paths bounded to `GITHUB_WORKSPACE`.
- Publish deterministic findings and clean-rerun fixtures shared with
  PatchHive, including exact reproduction commands and SHA-256 digests.
- Keep the scanner offline, dependency-free, fail-closed, and backward
  compatible with native JSON schema 1 and existing SARIF consumers.

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
