from conftest import StubDetector

from releaseguard.scanner import iter_files, scan_directory


def test_scan_directory_finds_entities_across_file_types(tmp_path):
    (tmp_path / "notes.txt").write_text("Contact John Smith at john@example.com\n")
    (tmp_path / "data.csv").write_text("name,phone\nJohn Smith,555-123-4567\n")

    result = scan_directory(str(tmp_path), StubDetector())

    assert result.files_scanned == 2
    assert result.entity_counts["PERSON"] == 2
    assert result.entity_counts["EMAIL_ADDRESS"] == 1
    assert result.entity_counts["PHONE_NUMBER"] == 1
    assert len(result.findings) == 4


def test_scan_directory_skips_unreadable_formats(tmp_path):
    (tmp_path / "model.bin").write_bytes(b"\x00\x01\x02")
    (tmp_path / "notes.txt").write_text("nothing sensitive here\n")

    result = scan_directory(str(tmp_path), StubDetector())

    assert result.files_scanned == 1
    assert result.files_skipped == [str(tmp_path / "model.bin")]


def test_scan_directory_skips_vcs_and_dependency_dirs(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("john@example.com\n")
    (tmp_path / "notes.txt").write_text("john@example.com\n")

    result = scan_directory(str(tmp_path), StubDetector())

    assert result.files_scanned == 1
    assert result.entity_counts["EMAIL_ADDRESS"] == 1


def test_scan_directory_accepts_a_single_file(tmp_path):
    path = tmp_path / "notes.txt"
    path.write_text("john@example.com\n")

    result = scan_directory(str(path), StubDetector())

    assert result.files_scanned == 1
    assert result.entity_counts["EMAIL_ADDRESS"] == 1


def test_finding_locations_are_populated_from_the_source_fragment(tmp_path):
    path = tmp_path / "data.csv"
    path.write_text("name,email\nJohn Smith,john@example.com\n")

    result = scan_directory(str(tmp_path), StubDetector())

    email_finding = next(f for f in result.findings if f.entity_type == "EMAIL_ADDRESS")
    assert email_finding.file_path == str(path)
    assert email_finding.field_name == "email"
    assert email_finding.line_number == 2


def test_iter_files_is_sorted_and_recursive(tmp_path):
    (tmp_path / "b.txt").write_text("b")
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "a.txt").write_text("a")

    files = iter_files(str(tmp_path))

    assert files == sorted(files)
    assert str(sub / "a.txt") in files
    assert str(tmp_path / "b.txt") in files
