"""JSON / JSONL reader -- one fragment per string leaf value in the structure."""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

from releaseguard.readers.base import FileReader, TextFragment

JSON_EXTENSIONS = (".json", ".jsonl", ".ndjson")


class JsonReader(FileReader):
    format_name = "json"

    def matches(self, path: str) -> bool:
        return path.lower().endswith(JSON_EXTENSIONS)

    def read_fragments(self, path: str) -> Iterator[TextFragment]:
        # A malformed line/file or adversarially deep nesting (Python's
        # default recursion limit is a real, reachable ceiling, not a
        # purely theoretical one) is skipped rather than left to crash
        # the whole scan -- see `redactor.py`'s `_redact_json_file` for
        # why redaction must mirror this same handling exactly.
        is_lines = path.lower().endswith((".jsonl", ".ndjson"))
        with open(path, encoding="utf-8", errors="replace") as f:
            if is_lines:
                for line_number, line in enumerate(f, start=1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                        yield from self._walk(record, line_number, "")
                    except (json.JSONDecodeError, RecursionError):
                        continue
            else:
                try:
                    record = json.load(f)
                    yield from self._walk(record, None, "")
                except (json.JSONDecodeError, RecursionError):
                    return

    def _walk(self, value: Any, line_number: int | None, path: str) -> Iterator[TextFragment]:
        if isinstance(value, str):
            if value.strip():
                yield TextFragment(text=value, line_number=line_number, field_name=path or None)
        elif isinstance(value, dict):
            for key, sub_value in value.items():
                sub_path = f"{path}.{key}" if path else key
                yield from self._walk(sub_value, line_number, sub_path)
        elif isinstance(value, list):
            for index, sub_value in enumerate(value):
                sub_path = f"{path}[{index}]"
                yield from self._walk(sub_value, line_number, sub_path)
