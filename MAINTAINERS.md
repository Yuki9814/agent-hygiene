# Maintainers

## Current maintainer

- [@Yuki9814](https://github.com/Yuki9814) — repository administration,
  triage, security coordination, release approval, and publishing.

This file records responsibilities, not project adoption or contributor count.
New maintainers are added only after sustained reviewed contributions and an
explicit repository change.

## Decision process

Routine fixes use pull requests and normal review. Rule behavior, output
contracts, trust boundaries, and release automation require:

- a written rationale and false-positive analysis;
- focused regression tests;
- a passing synthetic corpus evaluation;
- compatibility notes when machine-readable output changes.

Security-sensitive details use private vulnerability reporting until a fix is
available.

## Release checklist

1. Confirm `CHANGELOG.md` and all three version declarations agree.
2. Run unit tests, corpus evaluation, canonical evidence validation, self-scan,
   local Action integration, the default 100k-file benchmark, distribution
   build, and wheel smoke installation.
3. Review the complete diff and confirm no fixture or evidence document
   contains a live secret, raw repository content, an absolute local path, or
   another private artifact.
4. Merge the release pull request.
5. Create and push the matching `vMAJOR.MINOR.PATCH` tag.
6. Let the tag workflow build checksums and create the GitHub release. If that
   tag or release already exists, stop instead of overwriting assets.
7. Install the published wheel in a clean environment, run the published Action
   smoke workflow, and record both checks in the release notes.

Repository workflows pin actions to full commit SHAs. Dependabot proposes
updates; the maintainer reviews the upstream release and resulting CI before
merging the new pin. `CODEOWNERS` marks scanner, workflow, corpus, packaging,
and security policy changes for maintainer review; repository branch rules must
require that review for enforcement.

PyPI publishing is not part of the current process. Documentation must not
claim that a package-index release exists until publishing is independently
verified.

The evidence summary is recomputed from the versioned documents; never edit a
reported metric by hand. A release may state “independently validated” only
when the contract itself reports that status. Pull-request CI uses broad
functional benchmark guardrails; the release benchmark is the 20-run,
2.5-second/150-MiB contract. A release-gate failure needs an investigated code
or environment change; do not raise the threshold merely to make a release
pass.
