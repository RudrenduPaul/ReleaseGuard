import json

import pytest
from conftest import StubDetector

from releaseguard.redactor import redact_directory
from releaseguard.scanner import scan_directory
from releaseguard.types import RedactionStrategy


def test_redact_directory_masks_text_by_default(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "notes.txt").write_text("Contact john@example.com now\n")

    scan_result = scan_directory(str(source), StubDetector())
    output = tmp_path / "out"
    result = redact_directory(scan_result, str(output))

    redacted_text = (output / "notes.txt").read_text()
    assert "john@example.com" not in redacted_text
    assert "*" in redacted_text
    assert result.entities_redacted["EMAIL_ADDRESS"] == 1


def test_redact_directory_hash_strategy_is_deterministic(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "notes.txt").write_text("john@example.com\n")

    scan_result = scan_directory(str(source), StubDetector())
    output = tmp_path / "out"
    redact_directory(scan_result, str(output), strategy=RedactionStrategy.HASH)

    redacted_text = (output / "notes.txt").read_text()
    assert "john@example.com" not in redacted_text
    assert len(redacted_text.strip()) == 64  # sha256 hex digest length


def test_redact_directory_remove_strategy_deletes_the_span(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "notes.txt").write_text("Email: john@example.com end\n")

    scan_result = scan_directory(str(source), StubDetector())
    output = tmp_path / "out"
    redact_directory(scan_result, str(output), strategy=RedactionStrategy.REMOVE)

    redacted_text = (output / "notes.txt").read_text()
    assert "john@example.com" not in redacted_text
    assert redacted_text.strip() == "Email:  end"


def test_redact_directory_accepts_a_single_file_as_the_source(tmp_path):
    path = tmp_path / "notes.txt"
    path.write_text("john@example.com\n")

    scan_result = scan_directory(str(path), StubDetector())
    output = tmp_path / "out"
    result = redact_directory(scan_result, str(output))

    assert (output / "notes.txt").exists()
    assert result.entities_redacted["EMAIL_ADDRESS"] == 1


def test_redact_directory_never_mutates_the_source(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    original = "john@example.com\n"
    (source / "notes.txt").write_text(original)

    scan_result = scan_directory(str(source), StubDetector())
    redact_directory(scan_result, str(tmp_path / "out"))

    assert (source / "notes.txt").read_text() == original


def test_redact_directory_csv_redacts_only_matching_cells(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "data.csv").write_text("name,email\nJohn Smith,john@example.com\n")

    scan_result = scan_directory(str(source), StubDetector())
    output = tmp_path / "out"
    redact_directory(scan_result, str(output), strategy=RedactionStrategy.REMOVE)

    redacted_text = (output / "data.csv").read_text()
    assert "john@example.com" not in redacted_text
    assert "John Smith" not in redacted_text  # StubDetector also matches PERSON


def test_redact_directory_json_preserves_structure(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "data.json").write_text(json.dumps({"contact": "john@example.com", "id": 1}))

    scan_result = scan_directory(str(source), StubDetector())
    output = tmp_path / "out"
    redact_directory(scan_result, str(output), strategy=RedactionStrategy.REMOVE)

    redacted = json.loads((output / "data.json").read_text())
    assert redacted["id"] == 1
    assert "john@example.com" not in redacted["contact"]


def test_redact_directory_jsonl_redacts_each_record_independently(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "data.jsonl").write_text('{"text": "john@example.com"}\n{"text": "no pii here"}\n')

    scan_result = scan_directory(str(source), StubDetector())
    output = tmp_path / "out"
    redact_directory(scan_result, str(output), strategy=RedactionStrategy.REMOVE)

    lines = (output / "data.jsonl").read_text().splitlines()
    assert json.loads(lines[0])["text"] == ""
    assert json.loads(lines[1])["text"] == "no pii here"


def test_redact_directory_copies_unreadable_formats_through_unchanged(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "model.bin").write_bytes(b"\x00\x01\x02")

    scan_result = scan_directory(str(source), StubDetector())
    output = tmp_path / "out"
    redact_directory(scan_result, str(output))

    assert (output / "model.bin").read_bytes() == b"\x00\x01\x02"


def test_redact_directory_refuses_to_overwrite_a_nonempty_dir_by_default(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "notes.txt").write_text("hello\n")

    output = tmp_path / "out"
    output.mkdir()
    (output / "existing.txt").write_text("do not touch\n")

    scan_result = scan_directory(str(source), StubDetector())

    with pytest.raises(FileExistsError):
        redact_directory(scan_result, str(output))

    # The overwrite guard means a second pass with overwrite=True succeeds.
    redact_directory(scan_result, str(output), overwrite=True)
    assert (output / "notes.txt").exists()
