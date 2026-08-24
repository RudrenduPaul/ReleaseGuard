# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

- Bump `cryptography` (indirect dependency) from 48.0.1 to 50.0.0 (#2).

## [0.1.3] - 2026-08-11

- Improve MCP tool description quality so agent clients (Claude Desktop,
  MCP Inspector, etc.) get clearer tool descriptions for `scan_directory_tool`,
  `redact_directory_tool`, and `package_release_tool`.

## [0.1.2] - 2026-08-11

- Fix a path-existence check bypass in the MCP tool handlers
  (`scan_directory_tool`, `redact_directory_tool`, `package_release_tool`):
  they previously skipped the CLI's path-existence check and returned a
  false success on a nonexistent path. Each tool now checks the path first
  and returns a structured error, and every handler is wrapped so an
  unexpected exception returns an error instead of crashing the server.
- Add a README "MCP Server" section documenting the real tool signatures
  and a Claude Desktop config using the `releaseguard mcp` subcommand, plus
  an ownership-proof `mcp-name` comment.
- Add `server.json` for the Official MCP Registry.

## [0.1.1] - 2026-08-09

- Rewrite README with a verified competitor comparison, FAQ, and more EU AI
  Act detail.
- Fix README CLI reference to match actual `releaseguard --help` output.
- Add missing demo GIFs (entity-filtered scan, full CLI help), make all demo
  GIFs consistent in dimensions, embed the remaining GIFs in the README, and
  add traffic-light window dots.
- Add CodeQL security scanning workflow.
- Improve README structure and searchability per portfolio design study.
- Commit `uv.lock` for reproducible installs.
- Credit Sourav Nandy in LICENSE.
- `releaseguard-cli` published to npm (thin launcher shim) alongside PyPI.

## [0.1.0] - 2026-08-03

Initial release.

- `releaseguard scan` -- Presidio-backed PII/secret scanning across CSV,
  JSON/JSONL, and plain-text files, human-readable and `--json` output.
- `releaseguard redact` -- writes a redacted copy (mask/hash/remove
  strategies) via `presidio-anonymizer`, never mutates the source.
- `releaseguard package` -- generates a Hugging Face dataset/model card and
  an EU AI Act Art. 53(1)(d) training-data-summary template from real scan
  results.
- `releaseguard mcp` -- MCP server (stdio) exposing `scan_directory_tool`,
  `redact_directory_tool`, `package_release_tool`.
- `.well-known/agent.json` for A2A-style agent discovery.
- Published as `releaseguard-cli` on both PyPI (Python core) and npm (thin
  launcher shim).
