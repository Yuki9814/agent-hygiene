# Changelog

All notable changes are documented here. This project follows semantic versioning.

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
