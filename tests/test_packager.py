import os

import pytest
from conftest import StubDetector

from releaseguard.packager import build_release_bundle
from releaseguard.redactor import redact_directory
from releaseguard.scanner import scan_directory


def test_build_release_bundle_dataset_kind_writes_dataset_card_and_summary(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "notes.txt").write_text("john@example.com\n")
    scan_result = scan_directory(str(source), StubDetector())

    output = tmp_path / "bundle"
    result = build_release_bundle(scan_result, str(output), source_kind="dataset")

    assert result.dataset_card_path is not None
    assert result.model_card_path is None
    assert os.path.exists(result.dataset_card_path)
    assert os.path.exists(result.eu_ai_act_summary_path)


def test_build_release_bundle_model_kind_writes_model_card_only(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "config.json").write_text('{"note": "john@example.com"}')
    scan_result = scan_directory(str(source), StubDetector())

    output = tmp_path / "bundle"
    result = build_release_bundle(scan_result, str(output), source_kind="model")

    assert result.model_card_path is not None
    assert result.dataset_card_path is None


def test_build_release_bundle_both_kind_writes_both_cards(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "notes.txt").write_text("hello\n")
    scan_result = scan_directory(str(source), StubDetector())

    output = tmp_path / "bundle"
    result = build_release_bundle(scan_result, str(output), source_kind="both")

    assert result.dataset_card_path is not None
    assert result.model_card_path is not None


def test_build_release_bundle_rejects_invalid_source_kind(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "notes.txt").write_text("hello\n")
    scan_result = scan_directory(str(source), StubDetector())

    with pytest.raises(ValueError):
        build_release_bundle(scan_result, str(tmp_path / "bundle"), source_kind="invalid")


def test_build_release_bundle_includes_redaction_context_in_cards(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "notes.txt").write_text("john@example.com\n")
    scan_result = scan_directory(str(source), StubDetector())
    redaction_result = redact_directory(scan_result, str(tmp_path / "redacted"))

    output = tmp_path / "bundle"
    result = build_release_bundle(scan_result, str(output), redaction_result=redaction_result)

    card_text = open(result.dataset_card_path).read()
    assert "redacted" in card_text.lower()


def test_build_release_bundle_rejects_unknown_compliance_template(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "notes.txt").write_text("hello\n")
    scan_result = scan_directory(str(source), StubDetector())

    with pytest.raises(ValueError):
        build_release_bundle(
            scan_result,
            str(tmp_path / "bundle"),
            compliance_templates=["not-a-real-template"],
        )
