# Pinned local canary collection

`collect` fills the step between selecting a consenting public repository and
reviewing its scanner findings. Given a public-canary manifest and an ordinary
local Git clone, it reads the selected 40-character commit from the clone's
object database, scans an isolated snapshot, and writes a new local bundle.

## Prepare and collect

Obtain public consent for the exact revision using the existing
[consent form](../.github/ISSUE_TEMPLATE/canary-consent.yml). The operator must
check the consent and obtain the repository from a trusted source. Collection
does not contact GitHub, check a remote origin, authenticate the commit's author,
or verify that a consent link authorizes a scan.

Use the existing [manifest contract](evidence.md). Each selected entry needs
`repository_id`, a canonical public GitHub `repository_url`, a full `revision`,
`consent_url`, and `selection_reason`; study `limitations` are also required.
The selected commit and all of its blobs must already exist locally.

```bash
agent-hygiene collect ./repository-clone \
  --manifest ./public_canary_manifest.json \
  --repository-id example-project \
  --output ./canary-bundle

agent-hygiene evidence ./canary-bundle/evidence --format json
```

`--output` must be a new path whose parent directory already exists, and its
resolved path must be outside the resolved source checkout and its `.git`
directory. A symlinked parent cannot bypass this boundary. Existing files,
directories, and symlinks are refused. All output is staged and its evidence
layer is validated before the destination is created. A publication error
removes the collector's newly created destination. Do not share that
destination with another writer while collection runs.
The validated `evidence/` directory is installed last in a single rename. A
forced process termination can leave a partial bundle without that directory;
such a bundle is not a completed collection. Retry to a new destination. This
is not a crash-durable transaction for the entire bundle.

## Bundle layout and review

```text
canary-bundle/
  .gitignore                 # excludes /private/
  evidence/
    public_canary_manifest.json
    observation/
      example-project.json
  private/
    result.json
```

The evidence manifest contains only the selected repository and retains study
limitations. The observation contains rule IDs, relative paths, line numbers,
stable finding IDs, completeness, source revision, and the SHA-256 digest of
the exact UTF-8 bytes in `private/result.json`. Multiple raw findings at the
same rule/path/line are represented by one observation location, matching the
existing evidence contract.

Only copy `evidence/` into a public study, after reviewing its paths and metadata.
The private JSON deliberately retains the scanner's normal finding details for
out-of-band review. Portable output omits the checkout root; it does **not**
make all source snippets public-safe. The new bundle/private directories have
mode 0700 and JSON files mode 0600 where filesystem permission bits apply.
Do not commit, upload, or attach `private/` automatically. The generated
`.gitignore` is a convenience, not an access-control boundary.

A reviewer can recompute SHA-256 over `private/result.json` and compare it with
the observation's `result_sha256`. Human reviews bind to the SHA-256 of the
observation JSON bytes via `observation_sha256`, as in the existing contract.
`evidence` validates the public layer; it does not read the separate private
result or independently authenticate either digest.

## Determinism and source boundary

- The manifest revision selects the source even when HEAD moves or the working
  directory has uncommitted, staged, untracked, or ignored files.
- Git reads run against isolated metadata with only the clone's local object
  store. Source Git configuration, includes, hooks, filters, replacement refs,
  `export-ignore`, and inherited Git routing variables are not used. Missing
  objects fail; no lazy fetch or network downloader is started.
- Commit and blob object hashes are checked before scanning. These checks bind
  local bytes; they do not establish GitHub provenance or author authenticity.
- Collection inspects the `.git/objects` root and its entries before reading
  objects. The root and its internal entries must not be symlinks; alternate
  stores named `info/alternates` or `info/http-alternates`, non-regular entries,
  and an object-store listing over 100,000 entries are refused.
- The local object store must remain unchanged for the duration of collection.
  Concurrent fetch, garbage collection, repack, prune, or other object-database
  mutation is unsupported; use a stable local clone and retry if it changes.
- Collection uses a fixed default `Config()` and disables the baseline,
  rule/path ignore rules, and inline suppression. A snapshot's
  `.agent-hygiene.json` is repository content rather than collection policy;
  it cannot hide canary findings, and the canary suppression audit is empty.
  Ordinary `scan` keeps its existing configuration and suppression behavior.
- The source revision and scope identity come from the validated manifest.
  Scan JSON/observation output is deterministic for the same source, manifest,
  scanner version, and supported filesystem behavior. There are no timestamps
  or random snapshot paths in those documents.

## Limits and exit status

The collector supports ordinary SHA-1 Git clones with a `.git` directory.
Linked worktrees, bare repositories, SHA-256 repositories, Git LFS hydration,
and submodule expansion are not supported. A partial clone can be used only if
every required object is already present locally.

The tree is limited to 10,000 regular files, 16 MiB per file, and 64 MiB total
blob bytes; Git tree/commit responses are limited to 4 MiB. Each Git read has a
30-second deadline. Symlinks, submodules, unsafe/nonportable paths, and case or
Unicode normalization collisions are refused rather than silently skipped.
The normal scanner discovery range, default excludes, and 512 KiB
instruction-file limits still apply within the snapshot. Collection does not
promise to inspect every arbitrary file in the Git tree. The observation also
must satisfy the existing bounded evidence schema.

- `0`: a complete observation was collected. Findings may still exist; this is
  collection success, not a policy pass or an accuracy result.
- `2`: invalid input, unavailable Git/object, unsupported snapshot, or write
  failure. No completed bundle is published for these failures.
- `2` with a bundle: the scanner returned an incomplete observation. Inspect
  `private/result.json`; the evidence layer preserves `complete: false` and
  cannot contribute a complete observation to the independent-validation gate.

This command creates no consent, review, adjudication, endorsement, or adoption
record. The canonical study remains at zero recorded external reviewers and
zero consenting public repositories until actual evidence is obtained.

## Compatibility

`collect` is additive in v0.8. Existing scan, baseline, Action, JSON, SARIF,
finding-fingerprint, and evidence-v1 contracts are unchanged. Older clients can
validate the generated `evidence/` directory. To roll back the CLI, reinstall
v0.7; source repositories and their working trees have not been modified.
