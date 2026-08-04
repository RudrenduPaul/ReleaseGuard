import csv
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


def test_redact_directory_does_not_crash_on_malformed_json_that_scan_already_skipped(tmp_path):
    """Regression test: `scan` silently skips a malformed JSON file (0
    findings for it), but an earlier version of `redact_directory` called
    `json.load` on it with no error handling, so redacting the exact same
    directory `scan` had just succeeded against raised an unhandled
    `JSONDecodeError` and aborted the whole run. The file must now be
    written through unchanged instead, consistent with `scan`'s own
    handling of the same input.
    """
    source = tmp_path / "source"
    source.mkdir()
    (source / "broken.json").write_text("{not valid json")
    (source / "notes.txt").write_text("john@example.com\n")

    scan_result = scan_directory(str(source), StubDetector())
    assert (
        scan_result.files_scanned == 2
    )  # both files are "readable" by format, one just fails to parse

    output = tmp_path / "out"
    result = redact_directory(scan_result, str(output))  # must not raise

    assert (output / "broken.json").read_text() == "{not valid json"
    assert (output / "notes.txt").read_text() != "john@example.com\n"  # actually redacted
    assert result.entities_redacted["EMAIL_ADDRESS"] == 1


def test_redact_directory_does_not_crash_on_malformed_jsonl_line(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "data.jsonl").write_text('{"text": "john@example.com"}\nnot json at all\n')

    scan_result = scan_directory(str(source), StubDetector())
    output = tmp_path / "out"
    result = redact_directory(scan_result, str(output), strategy=RedactionStrategy.REMOVE)

    lines = (output / "data.jsonl").read_text().splitlines()
    assert json.loads(lines[0])["text"] == ""
    assert lines[1] == "not json at all"
    assert result.entities_redacted["EMAIL_ADDRESS"] == 1


def test_redact_directory_never_copies_a_symlinked_file_into_output(tmp_path):
    """Regression test for the core security finding: a symlink inside the
    scanned directory pointing at an unrelated host file was previously
    followed by `shutil.copy2`/`open()` and its real, unredacted content
    landed verbatim in the "redacted, safe for public release" output.
    """
    source = tmp_path / "source"
    source.mkdir()
    outside_secret = tmp_path / "outside-secret.pem"
    outside_secret.write_text("-----BEGIN PRIVATE KEY-----\nnot really\n")
    (source / "checkpoint.bin").symlink_to(outside_secret)
    (source / "real.txt").write_text("john@example.com\n")

    scan_result = scan_directory(str(source), StubDetector())
    output = tmp_path / "out"
    redact_directory(scan_result, str(output))

    assert not (output / "checkpoint.bin").exists()
    assert (output / "real.txt").exists()


def test_redact_directory_refuses_a_symlinked_root(tmp_path):
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    (real_dir / "notes.txt").write_text("john@example.com\n")
    link = tmp_path / "link"
    link.symlink_to(real_dir)

    scan_result = scan_directory(str(link), StubDetector())
    output = tmp_path / "out"
    result = redact_directory(scan_result, str(output))

    assert result.files_written == []


def test_redact_directory_rejects_an_output_path_that_is_an_existing_file(tmp_path):
    """Regression test: --output pointing at an existing regular file
    previously crashed with an uncaught NotADirectoryError from
    os.listdir() instead of the same clean FileExistsError every other
    "can't write here" case raises.
    """
    source = tmp_path / "source"
    source.mkdir()
    (source / "notes.txt").write_text("hello\n")
    output_as_file = tmp_path / "output-is-a-file"
    output_as_file.write_text("i am a file, not a directory\n")

    scan_result = scan_directory(str(source), StubDetector())

    with pytest.raises(FileExistsError):
        redact_directory(scan_result, str(output_as_file))


def test_redact_directory_csv_with_duplicate_headers_does_not_lose_data(tmp_path):
    """Regression test: `csv.DictReader`/`DictWriter` collapse duplicate
    column names into one dict key, so a CSV with header `email,note,email`
    previously lost the first `email` column's value entirely (never
    scanned) and duplicated the second column's value into both slots on
    write-back.
    """
    source = tmp_path / "source"
    source.mkdir()
    (source / "data.csv").write_text(
        "email,note,email\njohn@example.com,hi,552-000-1111 not an email\n"
    )

    scan_result = scan_directory(str(source), StubDetector())
    output = tmp_path / "out"
    redact_directory(scan_result, str(output), strategy=RedactionStrategy.REMOVE)

    rows = list(csv.reader((output / "data.csv").read_text().splitlines()))
    assert rows[0] == ["email", "note", "email"]
    # First "email" column had a real match and is redacted; the second
    # "email" column's distinct value must survive unchanged, not be
    # overwritten with the first column's (redacted) value or vice versa.
    assert "john@example.com" not in rows[1][0]
    assert rows[1][2] == "552-000-1111 not an email"


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
