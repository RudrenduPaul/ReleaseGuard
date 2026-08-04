"""Walk a directory, read every file with a matching reader, and run a detector over it."""

from __future__ import annotations

import os

from releaseguard.detectors.base import PIIDetector
from releaseguard.readers import DEFAULT_READERS, FileReader, get_reader_for
from releaseguard.types import Finding, ScanResult

# Directories never worth descending into for PII scanning -- version
# control internals and dependency/venv trees produce enormous false-work
# and never contain real dataset content.
SKIP_DIR_NAMES = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    ".mypy_cache",
    ".ruff_cache",
}


def iter_files(root: str) -> list[str]:
    """Recursively list every file under `root`, skipping VCS/dependency dirs."""
    matched: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIR_NAMES]
        for filename in filenames:
            matched.append(os.path.join(dirpath, filename))
    return sorted(matched)


def scan_directory(
    root_path: str,
    detector: PIIDetector,
    readers: list[FileReader] | None = None,
    language: str = "en",
) -> ScanResult:
    """Scan every readable file under `root_path` and return every finding.

    A single file (not a directory) is also accepted -- `root_path` is
    treated as a one-file directory in that case.
    """
    if os.path.isfile(root_path):
        candidate_paths = [root_path]
    else:
        candidate_paths = iter_files(root_path)

    findings: list[Finding] = []
    files_scanned = 0
    files_skipped: list[str] = []

    for path in candidate_paths:
        reader = get_reader_for(path, readers)
        if reader is None:
            files_skipped.append(path)
            continue

        files_scanned += 1
        for fragment in reader.read_fragments(path):
            fragment_findings = detector.analyze(fragment.text, language=language)
            for finding in fragment_findings:
                findings.append(
                    Finding(
                        file_path=path,
                        entity_type=finding.entity_type,
                        start=finding.start,
                        end=finding.end,
                        score=finding.score,
                        text_preview=finding.text_preview,
                        line_number=fragment.line_number,
                        field_name=fragment.field_name,
                        detector=finding.detector,
                    )
                )

    entity_counts: dict[str, int] = {}
    for finding in findings:
        entity_counts[finding.entity_type] = entity_counts.get(finding.entity_type, 0) + 1

    return ScanResult(
        root_path=root_path,
        files_scanned=files_scanned,
        files_skipped=files_skipped,
        findings=findings,
        entity_counts=entity_counts,
        detector_name=getattr(detector, "name", "unknown"),
        language=language,
    )


def default_readers() -> list[FileReader]:
    return list(DEFAULT_READERS)
