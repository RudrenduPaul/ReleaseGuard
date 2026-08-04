from releaseguard.model_card import generate_model_card
from releaseguard.types import RedactionResult, ScanResult


def _scan_result():
    return ScanResult(
        root_path="/model",
        files_scanned=2,
        files_skipped=[],
        findings=[],
        entity_counts={"API_KEY": 1},
    )


def test_model_card_lists_detected_entities():
    card = generate_model_card(_scan_result())
    assert "API_KEY" in card


def test_model_card_references_the_eu_ai_act_summary():
    card = generate_model_card(_scan_result())
    assert "eu-ai-act-training-summary.md" in card


def test_model_card_reports_redaction_strategy_when_provided():
    redaction_result = RedactionResult(
        source_root="/model",
        output_root="/out",
        strategy="hash",
        files_written=["/out/config.json"],
        entities_redacted={"API_KEY": 1},
    )
    card = generate_model_card(_scan_result(), redaction_result)
    assert "hash" in card
