from releaseguard.eu_ai_act import generate_eu_ai_act_summary
from releaseguard.types import ScanResult


def _scan_result(entity_counts=None):
    return ScanResult(
        root_path="/data",
        files_scanned=5,
        files_skipped=[],
        findings=[],
        entity_counts=entity_counts or {"EMAIL_ADDRESS": 3},
    )


def test_summary_covers_the_required_sections():
    summary = generate_eu_ai_act_summary(_scan_result())
    assert "Provider and Model Identification" in summary
    assert "Data Sources" in summary
    assert "Personal Data and PII Handling" in summary
    assert "Copyright-Protected Content" in summary
    assert "Update History" in summary


def test_summary_states_the_narrow_scope_explicitly():
    summary = generate_eu_ai_act_summary(_scan_result())
    assert "Art. 53(1)(d)" in summary
    assert "categorical-summary" in summary or "categorical" in summary


def test_summary_reflects_real_scan_counts_not_placeholders():
    summary = generate_eu_ai_act_summary(_scan_result({"EMAIL_ADDRESS": 3, "PHONE_NUMBER": 1}))
    assert "EMAIL_ADDRESS" in summary
    assert "3" in summary
    assert "PHONE_NUMBER" in summary


def test_summary_warns_when_no_redaction_has_been_applied():
    summary = generate_eu_ai_act_summary(_scan_result())
    assert "No redaction has been applied yet" in summary
