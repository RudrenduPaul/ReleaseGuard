"""Shared test fixtures.

Most tests use `StubDetector` instead of the real `PresidioDetector` --
it is a deterministic, dependency-free stand-in that finds a fixed set of
substrings, so scanner/redactor/card-generation logic can be tested without
needing spaCy model downloads on every run. `PresidioDetector` itself is
covered separately by the `@pytest.mark.integration` tests in
`test_presidio_detector.py`, which exercise the real Presidio pipeline
against `en_core_web_sm`.
"""

from __future__ import annotations

from releaseguard.detectors.base import PIIDetector
from releaseguard.types import Finding


class StubDetector(PIIDetector):
    """Finds exact, case-sensitive substring matches against a fixed table.

    Used only in tests -- never registered in `releaseguard.detectors`'s
    `get_detector()`, so it can never accidentally ship as a real backend.
    """

    name = "stub"

    def __init__(self, table: dict[str, str] | None = None) -> None:
        self.table = table or {
            "john@example.com": "EMAIL_ADDRESS",
            "555-123-4567": "PHONE_NUMBER",
            "John Smith": "PERSON",
        }

    def analyze(self, text: str, language: str = "en") -> list[Finding]:
        findings = []
        for substring, entity_type in self.table.items():
            start = text.find(substring)
            if start != -1:
                findings.append(
                    Finding(
                        file_path="",
                        entity_type=entity_type,
                        start=start,
                        end=start + len(substring),
                        score=0.85,
                        text_preview=substring,
                        detector=self.name,
                    )
                )
        return findings
