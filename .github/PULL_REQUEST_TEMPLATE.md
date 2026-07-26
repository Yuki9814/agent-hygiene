## What changed

Describe the user-visible behavior and trust boundary.

## Evidence

- [ ] `PYTHONPATH=src python -m unittest discover -s tests`
- [ ] `PYTHONPATH=src python -m agent_hygiene evaluate tests/corpus/manifest.json`
- [ ] `PYTHONPATH=src python -m agent_hygiene evidence evidence/v0.4.0 --format json`
- [ ] `PYTHONPATH=src python -m agent_hygiene scan . --min-score 85 --fail-on high`
- [ ] `PYTHONPATH=src python tools/benchmark_large_repo.py --format json`
- [ ] Distribution build and wheel smoke test, when packaging changed

Include exact results or explain why an item does not apply.

## Compatibility and risk

- JSON/SARIF fields changed:
- False-positive risk:
- Fail-closed behavior changed:
- Rollback:

## Fixture safety

- [ ] New fixtures are synthetic and contain no live secrets, private prompts,
      or confidential repository content.
- [ ] Evidence documents contain no raw repository content or absolute local
      paths, and every public canary has explicit consent at a fixed revision.
