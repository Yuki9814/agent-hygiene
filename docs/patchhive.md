# PatchHive handoff

`agent-hygiene` can create a portable native JSON report for local import into
[PatchHive](https://github.com/Yuki9814/PatchHive). This is a file handoff:
the scanner stays offline, and PatchHive parses the report inside the browser
without a backend, OAuth, or model execution.

## Local flow

Run a scan at a known source revision:

```bash
agent-hygiene scan . \
  --format json \
  --portable \
  --source-revision "$(git rev-parse --verify HEAD)" \
  --output agent-hygiene.json
```

The portable profile preserves native JSON schema 1 but omits
`summary.root`. When repository identity is available, the report retains the
opaque `summary.scope_fingerprint` used to reconcile later JSON or SARIF
reruns. `summary.source_revision` is a bounded declaration supplied by the
caller; it is not a signature.

Open PatchHive, preview `agent-hygiene.json`, and confirm the import. A finding
can be accepted only with a maintainer rationale. A finding is considered fixed
only when a later complete report with the same scope no longer contains its
normalized identity.

## GitHub Action flow

The Action can emit the same portable file before its final severity gate:

```yaml
- id: hygiene
  uses: Yuki9814/agent-hygiene@v0.5.1
  with:
    min-score: "85"
    fail-on: high
    json: agent-hygiene.json
- uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a
  if: always()
  with:
    name: agent-hygiene-json
    path: ${{ steps.hygiene.outputs.json }}
    if-no-files-found: error
```

The Action records `github.sha` as the declared source revision. The artifact
step remains explicit so repositories control retention and access.

## Frozen interoperability fixtures

Two synthetic reports under [`examples/patchhive`](../examples/patchhive)
exercise a same-scope finding and clean rerun:

| File | Source revision | SHA-256 |
| --- | --- | --- |
| `findings.json` | `1111111111111111111111111111111111111111` | `d12ea6afe46e47f364c11c9719f3cabd26ca74385d4676da30e618c4cde57c30` |
| `clean-rerun.json` | `2222222222222222222222222222222222222222` | `2a7d3b63421928900d5b3974eb8d8cd39e21e42f276b12873ca7115de38dd9f2` |

Regenerate them from source:

```bash
PYTHONPATH=src python tools/generate_patchhive_fixture.py findings
PYTHONPATH=src python tools/generate_patchhive_fixture.py clean-rerun
```

The pair proves only that the two public contracts interoperate
deterministically. It represents 0 external maintainers, 0 consenting
repositories, and no independent validation.
