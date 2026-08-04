# Changelog

All notable changes to this project are documented in this file.

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
- Published as `releaseguard-cli` on PyPI (Python core). The npm launcher
  shim is built and ready but not yet published.
