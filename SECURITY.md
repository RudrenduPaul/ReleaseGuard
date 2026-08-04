# Security Policy

## Reporting a vulnerability

Please report security issues privately via [GitHub Security
Advisories](https://github.com/RudrenduPaul/ReleaseGuard/security/advisories/new)
rather than a public issue. Include:

- A description of the vulnerability and its impact
- Steps to reproduce
- The affected version(s)

You should receive an initial response within 5 business days. We'll work
with you to confirm the issue, assess severity, and coordinate a fix and
disclosure timeline.

## Scope

ReleaseGuard scans, redacts, and packages dataset/model directories entirely
**locally**. It never transmits a scan target, scan result, or redacted
output to a remote service. In scope for security reports:

- The CLI (`scan`, `redact`, `package`) and its file readers
- The redaction logic (`redactor.py`) and its interaction with
  `presidio-anonymizer`
- The generated release bundle (dataset/model cards, EU AI Act summary) and
  whether it can leak unredacted content that a user reasonably expected to
  be sanitized
- The MCP server (`releaseguard mcp`)
- The npm launcher shim

**Path handling:** `scan`/`redact`/`package` accept a filesystem path
argument and read/write within it. A vulnerability report involving path
traversal, symlink handling, or output-directory overwrite behavior is in
scope.

**Not in scope:** Presidio's own detection accuracy or recognizer logic.
File a report with [Presidio](https://github.com/data-privacy-stack/presidio)
directly for anything about what it does or doesn't detect; ReleaseGuard
calls Presidio's public API and does not modify its behavior.

## Supported versions

Only the latest published release on PyPI/npm receives security fixes.
