# Roadmap

The roadmap is organized around evidence gates rather than feature count.

## v0.3 — auditable preview

- [x] Versioned positive and negative synthetic corpus.
- [x] Machine-readable precision and recall report with CI gates.
- [x] Versioned JSON metadata and richer backward-compatible SARIF.
- [x] Fail-closed Action input and repository path boundaries.
- [x] Maintainer, support, security, and release policies.

## v0.4 — independent validation

- [x] Publish a versioned evidence contract that separates repository selection,
  machine observations, human reviews, and adjudication.
- [x] Generate neutral blind-review packs without seeded labels or scanner
  output.
- [x] Define and enforce a repeatable 100,000-file performance fixture with p95
  latency and peak RSS gates.
- [ ] Have at least two maintainers or security practitioners review fixture
  labels without seeing scanner output.
- [ ] Add sanitized cases contributed through public issues and record their
  provenance.
- [ ] Publish per-rule corpus metrics in release notes.
- [ ] Test the Action in a public fixture repository on pull request and tag
  events.

Current external-evidence status: **0 recorded reviewers, 0 consenting public
repositories, not independently validated**. Infrastructure completion does not
complete the external review or canary gates.

## v0.5 — portable maintainer handoff

- [x] Let the Action emit bounded portable native JSON before its final policy
  gate.
- [x] Record a declared source revision without exposing an absolute checkout
  root.
- [x] Freeze a findings report and clean same-scope rerun for PatchHive
  interoperability regression.
- [ ] Validate the workflow with an external maintainer (`N=0`, not evaluated).

The fixture pair is synthetic compatibility evidence. It is not a consenting
repository, external review, or adoption result.

## v0.6 — evolving agent configuration coverage

- [x] Scan repository prompt files and custom agent profiles used by current
  Copilot and Claude-compatible workflows.
- [x] Discover supported agent instruction surfaces inside nested monorepo
  packages.
- [x] Inspect repository-scoped GitHub Copilot command, HTTP, and prompt hook
  configuration without treating reviewed direct script or session-start
  prompt hooks as findings.
- [x] Preserve stable rule IDs, output contracts, bounded reads, and the
  single-walk performance contract while expanding coverage.
- [ ] Record sanitized real-world examples for the new surfaces through the
  existing public-canary evidence process.

## v0.7 — auditable suppression decisions

- [x] Record baseline, configured rule/path, and inline-directive suppression
  decisions with stable rule IDs, normalized locations, fingerprints, sources,
  and static reasons.
- [x] Show suppression totals and bounded redaction-safe detail in text,
  Markdown, native JSON, and SARIF without changing schema version 1.
- [x] Keep the ledger bounded to 10,000 detail items while preserving exact
  counts, source totals, single-walk discovery, and zero runtime dependencies.
- [x] Add positive, negative, output-contract, privacy, and detail-bound tests.
- [ ] Validate suppression audit imports and review workflows with an external
  maintainer through the existing public-canary evidence process.

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
