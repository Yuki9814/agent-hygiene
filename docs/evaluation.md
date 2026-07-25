# Corpus evaluation

The evaluation corpus is a deterministic regression suite for scanner rules.
It makes rule changes reviewable by recording both the inputs and the expected
finding locations.

It is intentionally synthetic. Passing it does not prove that a rule will have
the same precision or recall on independent repositories.

## Reproduce the result

From a source checkout:

```bash
PYTHONPATH=src python -m agent_hygiene evaluate tests/corpus/manifest.json
PYTHONPATH=src python -m agent_hygiene evaluate \
  tests/corpus/manifest.json --format json
```

CI runs the same command. A gate miss returns exit code `1`. An invalid,
unreadable, escaping, or incomplete corpus returns exit code `2`.

## Method

Each case maps one or more inert `.fixture` source files to the names the
scanner discovers, such as `AGENTS.md`, `.mcp.json`, or a workflow path. The
evaluator:

1. validates the manifest and rejects absolute paths, traversal, symlinked
   sources, duplicate targets, unknown rules, and invalid thresholds;
2. copies the case into a new temporary repository;
3. runs the normal scanner with no baseline;
4. fails closed if discovery is incomplete;
5. matches expected and actual diagnostics by `(rule_id, path, line)`.

Across all cases:

```text
precision = true positives / (true positives + false positives)
recall    = true positives / (true positives + false negatives)
```

The version 1 manifest gates are 0.95 precision and 0.90 recall. Negative cases
are part of the precision denominator when they produce an unexpected finding.

## Manifest version 1

```json
{
  "version": 1,
  "gates": {
    "min_precision": 0.95,
    "min_recall": 0.9
  },
  "cases": [
    {
      "id": "prompt-override",
      "files": [
        {
          "source": "fixtures/positive/prompt-override.fixture",
          "target": "AGENTS.md"
        }
      ],
      "expected": [
        {
          "rule_id": "AH002",
          "path": "AGENTS.md",
          "line": 1
        }
      ]
    }
  ]
}
```

Sources are relative to the manifest directory. Targets are relative to the
temporary repository. Expected paths must name a target in the same case.

## Changing a rule

A rule change should add or update:

- a positive case for the behavior that must be detected;
- a nearby negative case for the most plausible false positive;
- a focused unit test when suppression, discovery, baseline, JSON, or SARIF
  behavior changes.

Review the case content rather than only the aggregate score. Seeded fixtures
can accidentally encode the implementation, so future release gates include an
independently reviewed corpus described in [ROADMAP.md](../ROADMAP.md).
