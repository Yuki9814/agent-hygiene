# Contributing

Thanks for making agent-controlled repositories easier to audit.

## Development

```bash
PYTHONPATH=src python -m unittest discover -s tests
PYTHONPATH=src python -m agent_hygiene scan .
python -m pip install build
python -m build
```

Runtime code should stay dependency-free. Tests should create temporary
fixtures instead of relying on local machine state.

## Rule changes

When adding or changing a rule:

- add a focused test
- include a remediation message
- keep false positives in mind
- document the rule in `docs/rules.md`

## Pull requests

Keep changes focused and describe the false-positive risk. Pull requests should
include the exact commands used for validation. Changes to discovery, baselines,
or reporters must include a regression test because those surfaces determine
whether CI can trust a passing result.
