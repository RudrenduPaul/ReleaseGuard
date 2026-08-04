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

## Known dependency finding: `cryptography` (transitive, via presidio-anonymizer)

`pip-audit` flags 3 disclosed CVEs (GHSA-m2h6-j472-rp4c, GHSA-g6cj-pr64-35w5,
GHSA-jwv3-5hgf-82ww) in `cryptography` 48.0.1, fixed in 49.0.0/50.0.0.
`presidio-anonymizer` 2.2.364 (the latest release as of this writing) pins
`cryptography<49.0.0`, so ReleaseGuard cannot take the fix without an
upstream release. Checked directly, not just noted and ignored:

- All three CVEs are in X.509 certificate chain validation and PKCS#7
  `EnvelopedData` decryption. ReleaseGuard never performs TLS/certificate
  verification or PKCS#7 decryption; it has no network calls at all (see
  the Scope section above).
- `presidio-anonymizer` imports `cryptography.hazmat.primitives` only for
  its `encrypt`/`decrypt` operators (AES-CBC). ReleaseGuard's `redact`
  command exposes `mask`/`hash`/`remove` only and never invokes
  `presidio-anonymizer`'s encrypt/decrypt operator, so even that unrelated
  code path is not reachable through ReleaseGuard.

Tracked as an accepted, currently-unfixable transitive finding. Re-check
`pip-audit` when `presidio-anonymizer` publishes a new release; update the
pin as soon as it allows `cryptography>=49.0.0`.
