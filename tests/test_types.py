from releaseguard.types import Finding, PackageResult, RedactionResult, ScanResult


def test_finding_to_dict_rounds_score():
    finding = Finding(
        file_path="a.txt",
        entity_type="EMAIL_ADDRESS",
        start=0,
        end=5,
        score=0.123456,
        text_preview="hello",
    )
    assert finding.to_dict()["score"] == 0.1235


def test_scan_result_to_dict_includes_total_findings():
    result = ScanResult(
        root_path="/data",
        files_scanned=2,
        files_skipped=[],
        findings=[
            Finding(
                file_path="a.txt",
                entity_type="EMAIL_ADDRESS",
                start=0,
                end=5,
                score=0.9,
                text_preview="x",
            )
        ],
    )
    payload = result.to_dict()
    assert payload["total_findings"] == 1
    assert payload["files_scanned"] == 2


def test_redaction_result_to_dict_sums_entities():
    result = RedactionResult(
        source_root="/src",
        output_root="/out",
        strategy="mask",
        files_written=["/out/a.txt"],
        entities_redacted={"EMAIL_ADDRESS": 2, "PERSON": 1},
    )
    assert result.to_dict()["total_redacted"] == 3


def test_package_result_to_dict_round_trips_all_fields():
    result = PackageResult(
        bundle_dir="/bundle",
        dataset_card_path="/bundle/README-dataset-card.md",
        model_card_path=None,
        eu_ai_act_summary_path="/bundle/eu-ai-act-training-summary.md",
        source_kind="dataset",
    )
    payload = result.to_dict()
    assert payload["source_kind"] == "dataset"
    assert payload["model_card_path"] is None
