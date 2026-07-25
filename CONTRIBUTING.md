# Contributing

Thanks for making agent-controlled repositories easier to audit.

## Development

```bash
PYTHONPATH=src python -m unittest discover -s tests
PYTHONPATH=src python -m agent_hygiene evaluate tests/corpus/manifest.json
PYTHONPATH=src python -m agent_hygiene scan .
python -m pip install build==1.2.2.post1
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
- add a positive and a nearby negative corpus case
- run the corpus evaluation and report any metric change

Do not tune a rule only to increase the seeded corpus score. Explain the
intended trust boundary and the most likely false positive in the pull request.

## Pull requests

Keep changes focused and describe the false-positive risk. Pull requests should
include the exact commands used for validation. Changes to discovery, baselines,
or reporters must include a regression test because those surfaces determine
whether CI can trust a passing result.

Use sanitized synthetic fixtures. Do not submit real credentials, private
prompts, private repository content, or sensitive SARIF evidence.

## Review and releases

The current maintainer reviews pull requests and release readiness. A change is
eligible for release only when the test matrix, corpus gate, self-scan, package
build, and wheel smoke test pass. The exact release procedure is recorded in
[MAINTAINERS.md](MAINTAINERS.md).
