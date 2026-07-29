# Security policy

## Supported versions

| Version | Supported |
| --- | --- |
| 0.5.x | yes |
| 0.4.x | critical fixes until 2026-10-27 |
| 0.3.x | critical fixes until 2026-10-26 |
| 0.2.x | critical fixes until 2026-10-26 |
| < 0.2 | no |

## Reporting a vulnerability

Use GitHub's private vulnerability reporting for findings that could expose
credentials, bypass scan completeness, or produce a misleading successful
result. Include a minimal reproduction and the affected version. Please do not
open a public issue until a fix is available.

Private reports are acknowledged when the maintainer next reviews the security
queue. The maintainer will confirm impact, coordinate a fix and disclosure, and
credit reporters who want public credit. No response-time guarantee is offered.

Do not include live secrets, private repository archives, or raw confidential
prompts. Prefer the smallest synthetic reproduction.

## Security boundaries

`agent-hygiene` reads repository files locally and does not make network
requests or call an LLM. Runtime code uses only the Python standard library.
The scanner treats relevant symlinks, non-regular files, read failures, and
oversized files as an incomplete scan. Untrusted inputs are opened through a
bounded descriptor, checked as the same regular file before reading, and
opened nonblocking on POSIX. This prevents FIFOs, Unix-domain sockets, and
final-component replacements from hanging a command or being accepted as
successfully read. Configuration, baselines, and JSON inputs have strict
regular-file, repository-boundary, byte, and parser limits. Non-POSIX
platforms retain descriptor type and identity verification, but this project
does not claim an equivalent no-hang guarantee for platform-specific special
endpoints without a nonblocking open primitive. Report evidence is redacted
before finding fingerprints or output are created. SARIF's
`primaryLocationLineHash` is derived from bounded source text, but the report
does not embed that text or an absolute source path. Human-readable output
escapes control characters. A passing result means the configured
deterministic checks completed; it is not proof that the repository is safe.

The descriptor check protects the final path component. It does not claim to
isolate a scan from a hostile process concurrently replacing parent
directories or mutating an already-open regular file. Run scans from a trusted
filesystem and checkout boundary when concurrent local attackers are in scope.

This tool provides deterministic policy checks; it is not a security
certification and does not replace threat modeling or code review.

Portable reports remove the absolute scan root but may still contain repository
paths, redacted finding evidence, an opaque repository-scope fingerprint, and a
declared source revision. Review reports before sharing them. Source-revision
and producer fields are not signatures and do not establish authenticity.
