# Agent instructions

This repository contains a zero-dependency Python CLI. Keep changes small,
well-tested, and easy to review.

## Commands

- Run tests: `PYTHONPATH=src python -m unittest discover -s tests`
- Run scanner locally: `PYTHONPATH=src python -m agent_hygiene scan .`
- Emit SARIF: `PYTHONPATH=src python -m agent_hygiene scan . --format sarif --output agent-hygiene.sarif`

## Style

- Use only the Python standard library at runtime.
- Keep output stable because tests may assert exact fields.
- Add or update a rule test when changing scanner behavior.
- Avoid broad rewrites unrelated to the requested fix.
