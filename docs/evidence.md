# Public evidence contract

Version 1 defines a bounded, reviewable record for future read-only canaries on
consenting public repositories. It is separate from the seeded synthetic
corpus: synthetic cases protect scanner behavior, while public evidence records
what was selected, observed, reviewed, and adjudicated.

Current status: **0 recorded reviewers, 0 consenting public repositories,
not independently validated**. The canonical empty manifest at
[`evidence/v0.4.0`](../evidence/v0.4.0) makes that status reproducible rather
than relying on a prose claim.

## Reproduce the status

To generate an observation from a manifest-selected commit already present in
a local clone, use the v0.8 [`collect` workflow](collection.md). It produces this
same evidence-v1 layout, with raw scanner JSON in a separate private directory;
it does not change the independent-validation gate or canonical study counts.

```bash
PYTHONPATH=src python -m agent_hygiene evidence \
  evidence/v0.4.0 --format json
PYTHONPATH=src python -m agent_hygiene evidence \
  evidence/v0.4.0 --format markdown
```

A valid evidence directory returns `0`. Invalid, unsafe, inconsistent, or
unreadable evidence returns `2`. The machine contract is published as
[`schemas/evidence-v1.schema.json`](../schemas/evidence-v1.schema.json);
runtime validation remains dependency-free and rejects unexpected fields.

## Directory layers

```text
evidence/v0.4.0/
  public_canary_manifest.json
  observation/*.json
  review/*.json
  adjudication/*.json
```

- `public_canary_manifest.json` records each public HTTPS repository, a fixed
  40-character commit, a public consent link, selection reason, and study
  limitations.
- `observation/*.json` records one bounded scanner observation per repository:
  completeness, a SHA-256 binding to the exact scanner result, and findings
  identified only by rule, relative path, and line.
- `review/*.json` records one review per reviewer and repository. Every observed
  finding must receive a true-positive or false-positive judgment.
- `adjudication/*.json` resolves conflicting reviewer verdicts for one observed
  finding. Unresolved conflicts remain visible and block independent-validation
  status.

Missing layer directories mean no documents in that layer. Symbolic links,
non-JSON files, duplicate identities, absolute or traversing paths, unbounded
documents, non-standard JSON numbers, and cross-layer revision or digest
mismatches fail validation.

## Review modes and metrics

`findings-only` review can measure the precision of observed findings, but it
cannot search the full repository surface for missed findings. Its recall is
therefore `null`.

`full-surface` review must include an explicit `false_negatives` array, including
an empty array when none were found. Recall is reported only when every selected
repository has a complete observation and at least one full-surface review.
Global and per-rule counts are recomputed from consistent or adjudicated
judgments. A zero precision or recall denominator produces `null`, never `1.0`.

The summary reports `independently_validated: true` only when all of these
conditions hold:

- at least 10 consenting repositories are recorded;
- every repository has a complete observation;
- every repository has at least one independent full-surface review;
- at least two distinct reviewers marked independent have performed
  full-surface reviews;
- no reviewer-verdict conflict remains unresolved.
- both global precision and recall have non-zero denominators.

This status is a protocol gate, not a claim that repository selection is
representative or that reviewer identity is cryptographically verified.
Limitations remain part of every summary.

## Privacy and provenance

Commit only the contract documents. Do not persist checkout roots, absolute
paths, credentials, private prompts, repository file contents, scanner evidence
snippets, or raw scanner JSON. `result_sha256` binds an observation to the exact
raw scanner JSON bytes reviewed out of band; the raw result is not committed.
Repository paths in observations and reviews must be relative POSIX paths.

Repository URLs use the canonical `https://github.com/owner/repository` form.
Host and owner/repository casing plus a trailing slash cannot create duplicate
canary identities. URL credentials, queries, fragments, ports, and whitespace
are rejected. Study limitations are required and reject control characters,
absolute local paths, and credential-like values in limitations and selection
reasons before they can enter committed evidence or a summary.

Consent must be public and specific to a fixed revision. The
[canary consent issue form](../.github/ISSUE_TEMPLATE/canary-consent.yml)
records permitted reporting scope and repository-specific limitations. Consent
does not imply adoption, endorsement, accuracy, or a passing result.

## Blind synthetic review packs

The corpus can be exported for label-blind review:

```bash
PYTHONPATH=src python -m agent_hygiene review-pack \
  tests/corpus/manifest.json --output blind-review.json
```

The deterministic pack uses neutral `C001`, `C002`, ... identifiers and a
corpus digest. Cases are sorted by a digest of their neutral target paths and
content before identifiers are assigned, so labeled manifest order is not
preserved. The pack contains target paths and synthetic fixture content, but
omits original case IDs, fixture source paths, expectations, positive/negative
labels, evaluation gates, and scanner output. Review-pack results remain
synthetic evidence and never count as public-canary validation.
