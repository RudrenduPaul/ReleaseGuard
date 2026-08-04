"""Integration tests against the real Presidio pipeline.

Marked `integration` (see pyproject.toml) since these need the
`en_core_web_sm` spaCy model installed -- CI installs it explicitly before
running this file; run `pytest -m integration` locally after
`python -m spacy download en_core_web_sm`.
"""

from __future__ import annotations

import pytest

from releaseguard.detectors.presidio_detector import PresidioDetector

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def detector() -> PresidioDetector:
    return PresidioDetector(spacy_model="en_core_web_sm", score_threshold=0.1)


def test_presidio_detector_finds_an_email_address(detector):
    findings = detector.analyze("Please contact me at john.doe@example.com for details.")
    entity_types = {f.entity_type for f in findings}
    assert "EMAIL_ADDRESS" in entity_types


def test_presidio_detector_returns_empty_list_for_blank_text(detector):
    assert detector.analyze("") == []
    assert detector.analyze("   ") == []


def test_presidio_detector_findings_carry_real_presidio_scores(detector):
    findings = detector.analyze("Email: john.doe@example.com")
    email_finding = next(f for f in findings if f.entity_type == "EMAIL_ADDRESS")
    assert 0.0 < email_finding.score <= 1.0
    assert email_finding.detector == "presidio"


def test_presidio_detector_respects_entities_filter():
    scoped = PresidioDetector(
        spacy_model="en_core_web_sm", score_threshold=0.1, entities=["EMAIL_ADDRESS"]
    )
    findings = scoped.analyze("Email john.doe@example.com, phone 212-555-0100")
    entity_types = {f.entity_type for f in findings}
    assert entity_types <= {"EMAIL_ADDRESS"}
