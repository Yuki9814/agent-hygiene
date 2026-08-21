# SARIF interoperability

For a complete scan, Agent Hygiene emits SARIF 2.1.0 with two partial
fingerprints for each result:

- `agentHygieneFingerprint/v1` is the existing finding identity used by native
  JSON and baselines.
- `primaryLocationLineHash` matches the algorithm used by GitHub's CodeQL
  Action SARIF uploader so code scanning can track a result when unrelated
  lines move its location.

The location fingerprint uses the 100 non-space/tab UTF-16 code units starting
at each line, normalizes CR, LF, and CRLF endings, performs unsigned 64-bit
rolling arithmetic with multiplier 37, and appends `:N` to distinguish
identical hashes in the same file. The implementation is checked against
[GitHub's published vectors](https://github.com/github/codeql-action/blob/7e8d8970f03ec5a78ab372fc0778e8e4194111a5/src/fingerprints.test.ts)
and an independent reference implementation.

Rules, inline suppression, JSON parser errors, SARIF regions, and location
fingerprints all count only CR, LF, and CRLF as line endings. Unicode VT, FF,
NEL, LINE SEPARATOR, and PARAGRAPH SEPARATOR characters remain within the
current SARIF line.

An oversized relevant file remains an incomplete, unsuccessful invocation and
only its first 512 KiB are scanned. A result receives
`primaryLocationLineHash` only when all 100 normalized code units needed for
that hash were observed inside the bounded prefix. A result too close to the
unsafe tail retains `agentHygieneFingerprint/v1` but omits
`primaryLocationLineHash`; Agent Hygiene never pads a truncated prefix or
labels a guessed value as GitHub-compatible.

This addition does not change rule IDs, the `Finding.fingerprint()` algorithm,
native JSON schema 1, or baseline version 2. Correcting the shared line
semantics does change the reported line and therefore the existing finding
fingerprint when a file previously treated VT, FF, NEL, LINE SEPARATOR, or
PARAGRAPH SEPARATOR as a line break. Review and regenerate only those affected
baseline entries after upgrading.

SARIF contains the opaque hash and the existing repository-relative artifact
URI; it does not include source text or an absolute checkout path. The hash is
derived from source context, so review a SARIF report before sharing it outside
the repository.

## Suppression audit

The run-level `properties.suppressionAudit` object makes suppressed findings
discoverable without turning policy text or finding evidence into SARIF data:

```json
{
  "count": 1,
  "by_source": {
    "baseline": 0,
    "ignore-rule": 0,
    "ignore-path": 1,
    "inline-directive": 0
  },
  "truncated": false,
  "items": [
    {
      "rule_id": "AH002",
      "path": "AGENTS.md",
      "line": 4,
      "fingerprint": "0123456789abcdef0123",
      "source": "ignore-path",
      "reason": "matched configured ignore path"
    }
  ]
}
```

`source` is one of `baseline`, `ignore-rule`, `ignore-path`, or
`inline-directive`. If more than one suppression would match, the scanner
records the first legacy decision in that order: configured rule, configured
path, baseline, then inline directive. Detail is capped at 10,000 items;
`count` and `by_source` remain exact and `truncated` signals omitted detail.
The ledger contains no raw directive, ignore pattern, message, or evidence.
Native JSON exposes the same object as `summary.suppression_audit`, and text
and Markdown reports render its count and available items. This is an additive
run property and does not change SARIF 2.1.0, existing result fields, native
JSON schema version 1, or baseline/finding fingerprint algorithms.

GitHub documents that code scanning uses
[`primaryLocationLineHash` for duplicate-alert prevention](https://docs.github.com/en/enterprise-cloud@latest/code-security/reference/code-scanning/sarif-files/sarif-support#data-for-preventing-duplicated-alerts).
