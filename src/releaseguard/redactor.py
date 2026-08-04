"""Apply redaction to a scanned directory and write a sanitized copy.

Never mutates the source directory. Every redaction call writes to a
separate `output_root`, which must not already exist as a non-empty
directory (see `redact_directory`'s `PermissionError` guard below) --
this is a deliberate default-safe behavior, not an oversight: a tool
whose job is preparing a directory for public release must never be able
to silently overwrite the only unredacted copy of sensitive source data.
"""

from __future__ import annotations

import csv
import json
import os
import shutil
from collections import defaultdict

from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig, RecognizerResult

from releaseguard.readers import FileReader, get_reader_for
from releaseguard.scanner import default_readers, iter_files
from releaseguard.types import Finding, RedactionResult, RedactionStrategy, ScanResult

_OPERATOR_BY_STRATEGY: dict[RedactionStrategy, OperatorConfig] = {
    RedactionStrategy.MASK: OperatorConfig(
        "mask", {"masking_char": "*", "chars_to_mask": 10_000, "from_end": False}
    ),
    RedactionStrategy.HASH: OperatorConfig("hash", {"hash_type": "sha256"}),
    RedactionStrategy.REMOVE: OperatorConfig("redact", {}),
}

# presidio_anonymizer ships no py.typed marker, so mypy sees AnonymizerEngine's
# own __init__ as untyped even with ignore_missing_imports=True (that flag
# only covers *missing* stubs, not an installed-but-untyped package).
_anonymizer = AnonymizerEngine()  # type: ignore[no-untyped-call]


def _anonymize_text(text: str, findings: list[Finding], strategy: RedactionStrategy) -> str:
    if not findings:
        return text
    results = [
        RecognizerResult(entity_type=f.entity_type, start=f.start, end=f.end, score=f.score)
        for f in findings
    ]
    operator = _OPERATOR_BY_STRATEGY[strategy]
    outcome = _anonymizer.anonymize(
        text=text, analyzer_results=results, operators={"DEFAULT": operator}
    )
    return outcome.text


def _findings_for_fragment(
    file_findings: list[Finding], line_number: int | None, field_name: str | None
) -> list[Finding]:
    return [f for f in file_findings if f.line_number == line_number and f.field_name == field_name]


def _redact_text_file(
    source_path: str, dest_path: str, file_findings: list[Finding], strategy: RedactionStrategy
) -> None:
    with (
        open(source_path, encoding="utf-8", errors="replace") as src,
        open(dest_path, "w", encoding="utf-8") as dst,
    ):
        for line_number, line in enumerate(src, start=1):
            stripped = line.rstrip("\n")
            fragment_findings = _findings_for_fragment(file_findings, line_number, None)
            redacted = _anonymize_text(stripped, fragment_findings, strategy)
            dst.write(redacted + "\n")


def _redact_csv_file(
    source_path: str, dest_path: str, file_findings: list[Finding], strategy: RedactionStrategy
) -> None:
    with open(source_path, newline="", encoding="utf-8", errors="replace") as src:
        reader = csv.DictReader(src)
        fieldnames = reader.fieldnames or []
        rows = list(reader)

    with open(dest_path, "w", newline="", encoding="utf-8") as dst:
        writer = csv.DictWriter(dst, fieldnames=fieldnames)
        writer.writeheader()
        for row_number, row in enumerate(rows, start=2):
            redacted_row = {}
            for field_name, value in row.items():
                fragment_findings = _findings_for_fragment(file_findings, row_number, field_name)
                redacted_row[field_name] = _anonymize_text(value or "", fragment_findings, strategy)
            writer.writerow(redacted_row)


def _redact_json_value(
    value: object,
    line_number: int | None,
    path: str,
    file_findings: list[Finding],
    strategy: RedactionStrategy,
) -> object:
    if isinstance(value, str):
        fragment_findings = _findings_for_fragment(file_findings, line_number, path or None)
        return _anonymize_text(value, fragment_findings, strategy)
    if isinstance(value, dict):
        return {
            key: _redact_json_value(
                sub_value, line_number, f"{path}.{key}" if path else key, file_findings, strategy
            )
            for key, sub_value in value.items()
        }
    if isinstance(value, list):
        return [
            _redact_json_value(sub_value, line_number, f"{path}[{i}]", file_findings, strategy)
            for i, sub_value in enumerate(value)
        ]
    return value


def _redact_json_file(
    source_path: str, dest_path: str, file_findings: list[Finding], strategy: RedactionStrategy
) -> None:
    """Redact a .json/.jsonl/.ndjson file.

    Mirrors `JsonReader.read_fragments`'s error handling exactly: a line
    (jsonl) or the whole file (json) that fails to parse produces no
    findings during scanning, so `file_findings` for it is already empty.
    Redaction must not treat that same failure differently -- an earlier
    version called `json.loads`/`json.load` here with no error handling,
    so a directory that `scan` completed successfully against (silently
    skipping the malformed content) would crash `redact`/`package`
    outright on the exact same input. A malformed line/file is written
    through unchanged instead, consistent with the "no reader claims this
    format -> copy through" policy in `redact_directory` below, and with
    `RecursionError` from adversarially deep nesting handled the same way
    (Python's default recursion limit is a real, reachable ceiling here,
    not a purely theoretical one).
    """
    is_lines = source_path.lower().endswith((".jsonl", ".ndjson"))
    with open(source_path, encoding="utf-8", errors="replace") as src:
        if is_lines:
            out_lines = []
            for line_number, raw_line in enumerate(src, start=1):
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                    redacted = _redact_json_value(record, line_number, "", file_findings, strategy)
                    out_lines.append(json.dumps(redacted))
                except (json.JSONDecodeError, RecursionError):
                    out_lines.append(line)
            content = "\n".join(out_lines) + "\n"
        else:
            raw_content = src.read()
            try:
                record = json.loads(raw_content)
                redacted = _redact_json_value(record, None, "", file_findings, strategy)
                content = json.dumps(redacted, indent=2) + "\n"
            except (json.JSONDecodeError, RecursionError):
                content = raw_content

    with open(dest_path, "w", encoding="utf-8") as dst:
        dst.write(content)


_WRITER_BY_FORMAT = {
    "text": _redact_text_file,
    "csv": _redact_csv_file,
    "json": _redact_json_file,
}


def redact_directory(
    scan_result: ScanResult,
    output_root: str,
    strategy: RedactionStrategy = RedactionStrategy.MASK,
    readers: list[FileReader] | None = None,
    overwrite: bool = False,
) -> RedactionResult:
    """Write a redacted copy of `scan_result.root_path` to `output_root`."""
    if os.path.exists(output_root) and os.listdir(output_root) and not overwrite:
        raise FileExistsError(
            f"{output_root!r} already exists and is not empty. "
            "Pass overwrite=True (--overwrite on the CLI) to redact into it anyway."
        )
    os.makedirs(output_root, exist_ok=True)

    readers = readers if readers is not None else default_readers()
    root = scan_result.root_path

    findings_by_file: dict[str, list[Finding]] = defaultdict(list)
    for finding in scan_result.findings:
        findings_by_file[finding.file_path].append(finding)

    if os.path.isfile(root):
        candidate_paths = [root]
    else:
        candidate_paths = iter_files(root)

    files_written: list[str] = []
    entities_redacted: dict[str, int] = defaultdict(int)

    for source_path in candidate_paths:
        rel = (
            os.path.relpath(source_path, root)
            if os.path.isdir(root)
            else os.path.basename(source_path)
        )
        dest_path = os.path.join(output_root, rel)
        os.makedirs(os.path.dirname(dest_path) or ".", exist_ok=True)

        reader = get_reader_for(source_path, readers)
        file_findings = findings_by_file.get(source_path, [])

        if reader is None:
            # No reader claims this format -- copy through unchanged rather
            # than silently dropping it from the release bundle. See
            # SECURITY.md's scope note: files ReleaseGuard cannot parse as
            # text/CSV/JSON are not scanned, and are not redacted either.
            shutil.copy2(source_path, dest_path)
        else:
            writer = _WRITER_BY_FORMAT[reader.format_name]
            writer(source_path, dest_path, file_findings, strategy)

        files_written.append(dest_path)
        for finding in file_findings:
            entities_redacted[finding.entity_type] += 1

    return RedactionResult(
        source_root=root,
        output_root=output_root,
        strategy=strategy.value,
        files_written=files_written,
        entities_redacted=dict(entities_redacted),
    )


__all__ = ["redact_directory"]
