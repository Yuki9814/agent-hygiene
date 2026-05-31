# Contributing

Thanks for making agent-controlled repositories easier to audit.

## Development

```bash
PYTHONPATH=src python -m unittest discover -s tests
PYTHONPATH=src python -m agent_hygiene scan .
```

Runtime code should stay dependency-free. Tests should create temporary
fixtures instead of relying on local machine state.

## Rule changes

When adding or changing a rule:

- add a focused test
- include a remediation message
- keep false positives in mind
- document the rule in `docs/rules.md`
