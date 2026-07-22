# Changelog

All notable changes are documented here. This project follows semantic versioning.

## 0.2.0 - 2026-07-22

- Fail closed when relevant files are symlinked, unreadable, or oversized.
- Report discovery issues in text, Markdown, JSON, and SARIF output.
- Mark incomplete SARIF invocations as unsuccessful.
- Use stable hashed SARIF partial fingerprints without exposing evidence text.
- Include line locations in baseline fingerprints to prevent collisions.
- Expand CI coverage through Python 3.13 and verify distribution builds.

## 0.1.0 - 2026-05-31

- Initial deterministic scanner, CLI, GitHub Action, baselines, and SARIF output.
