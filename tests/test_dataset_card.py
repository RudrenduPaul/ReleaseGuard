from releaseguard.dataset_card import generate_dataset_card
from releaseguard.types import RedactionResult, ScanResult


def _scan_result(entity_counts=None):
    if entity_counts is None:
        entity_counts = {"EMAIL_ADDRESS": 2, "PERSON": 1}
    return ScanResult(
        root_path="/data",
        files_scanned=3,
        files_skipped=[],
        findings=[],
        entity_counts=entity_counts,
    )


def test_dataset_card_lists_detected_entity_types():
    card = generate_dataset_card(_scan_result())
    assert "EMAIL_ADDRESS" in card
    assert "PERSON" in card
    assert "2" in card


def test_dataset_card_never_fabricates_unfound_fields():
    card = generate_dataset_card(_scan_result())
    assert "FILL IN" in card  # license/citation are left as explicit placeholders


def test_dataset_card_notes_when_no_pii_was_found():
    card = generate_dataset_card(_scan_result(entity_counts={}))
    assert "No PII entities were detected" in card


def test_dataset_card_reports_redaction_when_provided():
    scan_result = _scan_result()
    redaction_result = RedactionResult(
        source_root="/data",
        output_root="/out",
        strategy="mask",
        files_written=["/out/a.txt", "/out/b.txt"],
        entities_redacted={"EMAIL_ADDRESS": 2, "PERSON": 1},
    )
    card = generate_dataset_card(scan_result, redaction_result)
    assert "redacted" in card.lower()
    assert "3 entities" in card


def test_dataset_card_flags_unredacted_findings_when_no_redaction_given():
    card = generate_dataset_card(_scan_result())
    assert "scan only" in card.lower()
