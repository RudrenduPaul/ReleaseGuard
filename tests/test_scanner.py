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

    files, skipped_symlinks = iter_files(str(tmp_path))

    assert files == sorted(files)
    assert str(sub / "a.txt") in files
    assert str(tmp_path / "b.txt") in files
    assert skipped_symlinks == []


def test_iter_files_excludes_symlinked_files(tmp_path):
    """Regression test for a real security finding: a symlink inside a
    scanned directory pointing at an unrelated host file was previously
    followed and copied verbatim into "redacted" output by
    `redact_directory` (see `iter_files`'s docstring for the exploit).
    `iter_files` must never include a symlinked file in its file list.
    """
    outside_secret = tmp_path.parent / f"outside-secret-{tmp_path.name}.txt"
    outside_secret.write_text("TOP SECRET, not part of the dataset\n")
    (tmp_path / "checkpoint.bin").symlink_to(outside_secret)
    (tmp_path / "real.txt").write_text("real dataset content\n")

    files, skipped_symlinks = iter_files(str(tmp_path))

    assert str(tmp_path / "real.txt") in files
    assert str(tmp_path / "checkpoint.bin") not in files
    assert str(tmp_path / "checkpoint.bin") in skipped_symlinks
    outside_secret.unlink()


def test_scan_directory_refuses_a_symlinked_root(tmp_path):
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    (real_dir / "notes.txt").write_text("john@example.com\n")
    link = tmp_path / "link"
    link.symlink_to(real_dir)

    result = scan_directory(str(link), StubDetector())

    assert result.files_scanned == 0
    assert result.files_skipped == [str(link)]
    assert result.findings == []


def test_scan_directory_reports_skipped_symlinks_in_a_directory_walk(tmp_path):
    outside_secret = tmp_path.parent / f"outside-secret-scan-{tmp_path.name}.txt"
    outside_secret.write_text("john@example.com but this is not dataset content\n")
    (tmp_path / "linked.txt").symlink_to(outside_secret)
    (tmp_path / "real.txt").write_text("hello\n")

    result = scan_directory(str(tmp_path), StubDetector())

    assert result.files_scanned == 1  # only real.txt
    assert str(tmp_path / "linked.txt") in result.files_skipped
    assert result.findings == []  # the linked file's content was never read
    outside_secret.unlink()
