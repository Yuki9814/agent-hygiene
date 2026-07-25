# Roadmap

The roadmap is organized around evidence gates rather than feature count.

## v0.3 — auditable preview

- [x] Versioned positive and negative synthetic corpus.
- [x] Machine-readable precision and recall report with CI gates.
- [x] Versioned JSON metadata and richer backward-compatible SARIF.
- [x] Fail-closed Action input and repository path boundaries.
- [x] Maintainer, support, security, and release policies.

## v0.4 — independent validation

- [ ] Have at least two maintainers or security practitioners review fixture
  labels without seeing scanner output.
- [ ] Add sanitized cases contributed through public issues and record their
  provenance.
- [ ] Publish per-rule corpus metrics in release notes.
- [ ] Define and measure a repeatable large-repository performance fixture
  before setting latency or memory gates.
- [ ] Test the Action in a public fixture repository on pull request and tag
  events.

## v1.0 release gate

- [ ] Complete a 30-day canary across consenting public repositories.
- [ ] Triage every reported false positive and publish the disposition.
- [ ] Demonstrate install, JSON, SARIF, baseline, and Action compatibility from
  the previous minor release.
- [ ] Document rollback steps and verify the previous release artifacts remain
  installable.
- [ ] Require an independent release review for rule and workflow changes.

Dates are intentionally omitted until the evidence exists. Scope can change
through public issues, but release gates should not be weakened silently.
