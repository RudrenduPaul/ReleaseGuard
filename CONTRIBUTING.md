# Contributing to ReleaseGuard

## Setup

```bash
git clone https://github.com/RudrenduPaul/ReleaseGuard.git
cd ReleaseGuard
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,mcp]"
python -m spacy download en_core_web_sm
```

## Before you open a PR

```bash
ruff check .
ruff format --check .
mypy src/releaseguard
pytest --cov=releaseguard --cov-report=term-missing --cov-fail-under=80
```

All four must pass. CI runs the same checks, plus the `integration` test suite
against the real Presidio pipeline (`pytest -m integration`, needs
`en_core_web_sm` installed).

## Adding a new file format reader

ReleaseGuard's scanner and redactor depend only on the `FileReader` interface
in `src/releaseguard/readers/base.py`, never on a specific format's parsing
library directly. To add a new format (YAML, XML, a columnar format beyond
CSV):

1. Implement `FileReader` in a new module under `readers/`.
2. Register it in `readers/__init__.py`'s `DEFAULT_READERS` list.
3. Add the matching write-back function to `redactor.py`'s
   `_WRITER_BY_FORMAT` dict if the format supports redaction in place
   (most structured formats do).
4. Do not modify `scanner.py` or `detectors/`. If your reader yields
   `TextFragment` objects, the scanner and every detector already work
   with it.

## Adding a compliance-template target

`packager.py`'s `COMPLIANCE_TEMPLATES` registry is intentionally small in
v0.1 (`eu-ai-act` only). A second jurisdiction is a real possibility per the
project roadmap, but only once real users ask for one, not built
speculatively. If you're adding one:

1. Write a new `generate_<jurisdiction>_summary()` function, same shape as
   `eu_ai_act.py`'s `generate_eu_ai_act_summary()`: real scan/redaction data
   filled in, everything ReleaseGuard cannot verify left as an explicit
   `FILL_IN` placeholder.
2. Register it in `COMPLIANCE_TEMPLATES` with its own output filename.
3. State the regulation's actual scope precisely in the generated document's
   header, the same way `eu_ai_act.py` states Art. 53(1)(d)'s scope. Never
   imply a broader mandate than what's actually enacted and binding.

## What this project will not accept

- A change that makes ReleaseGuard claim to detect PII independently of, or
  more accurately than, Presidio. Detection is Presidio's; see the README's
  "What ReleaseGuard is not" section.
- A change that adds a "compliance-ready" or "certified" claim broader than
  the actual, narrow scope of whatever regulation the generated document
  targets. State the real scope, every time.
- A change that sends scan targets, scan results, or redacted output to a
  remote service. ReleaseGuard runs entirely local; see
  [SECURITY.md](SECURITY.md)'s scope section.
- A fabricated demand, star-count, or adoption claim in the README without a
  named, linkable, and independently checkable source.
