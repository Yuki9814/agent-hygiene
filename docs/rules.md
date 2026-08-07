# Rules

`agent-hygiene` uses deterministic checks. The goal is not to prove that a
repository is safe. The goal is to catch high-leverage mistakes before an AI
coding agent inherits them.

## AH001 Hidden Unicode in agent-controlled text

Flags bidirectional controls, zero-width characters, and other invisible
formatting characters that can hide or reorder instructions.

## AH002 Prompt override or secrecy instruction

Flags phrases such as "ignore previous instructions", instructions to reveal
system prompts, and text that asks the agent to hide actions from maintainers.

## AH003 Hardcoded credential-like value

Flags tokens that look like GitHub, OpenAI, AWS, Slack, or generic API secrets.
Placeholders such as `YOUR_TOKEN_HERE` are ignored.

## AH004 Dangerous shell or destructive command

Flags command snippets that include destructive shell usage, inline code
execution, global permission changes, or shell wrappers that can magnify prompt
injection.

## AH005 Network exfiltration pattern

Flags snippets that combine outbound network tools with sensitive paths or
secret-like terms.

## AH006 Risky MCP command shape

Flags MCP servers that launch a shell, run inline code with `-c` or `-e`, use
`npx @latest`, or rely on an unpinned package entrypoint.

## AH007 Inline secret in MCP environment

Flags MCP `env` values that appear to embed secrets instead of referencing an
external environment variable.

## AH008 Agentic workflow with broad trust boundary

Flags GitHub Actions workflows that combine risky triggers such as
`pull_request_target` or issue comments with write permissions or secrets.

## AH009 Missing verification command in instructions

Flags instruction files that do not mention concrete test, lint, typecheck, or
build commands.

## AH010 Stale path reference in instructions

Flags Markdown code spans that look like repository paths but no longer exist.

## AH011 Vague instruction block likely to drift

Flags instruction files that lean heavily on vague quality language without
concrete commands or paths.

## AH012 Duplicate root instruction files can drift

Flags repositories that keep multiple root-level agent instruction files without
an obvious generated or delegation note.

## AH013 Oversized agent instruction file

Flags very large instruction files that are hard to audit and expensive to pass
as context.

## AH014 Invalid MCP JSON

Flags MCP config files that cannot be parsed as JSON.

## AH015 Risky GitHub Copilot hook

Scans repository hook files under `.github/hooks/*.json` and inline hooks in
Copilot and cross-tool Claude settings. It flags invalid hook structures,
embedded command environment or HTTP header credentials, inline hook-input
uploads, credentials embedded in hook URLs, non-TLS transport, and external
HTTP destinations that need an explicit payload, retention, and firewall
review. A
direct command hook that calls a reviewed repository script or a valid
session-start prompt hook is not flagged merely for being a hook. Claude-format
matcher groups and all five Claude handler types are parsed in their nested
shape. Runtime header expansion through `allowedEnvVars` is not treated as an
inline credential. The external-endpoint finding is a trust-boundary review
prompt, not a claim that
the endpoint is malicious. See GitHub's
[Copilot hooks reference](https://docs.github.com/en/copilot/reference/hooks-reference)
for the current execution and payload model.
