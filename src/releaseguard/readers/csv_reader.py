"""CSV reader -- one fragment per non-empty cell, tagged with its column name."""

from __future__ import annotations

import csv
from collections.abc import Iterator

from releaseguard.readers.base import FileReader, TextFragment


class CsvReader(FileReader):
    format_name = "csv"

    def matches(self, path: str) -> bool:
        return path.lower().endswith(".csv")

    def read_fragments(self, path: str) -> Iterator[TextFragment]:
        with open(path, newline="", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row_number, row in enumerate(reader, start=2):  # header is line 1
                for field_name, value in row.items():
                    if value and value.strip():
                        yield TextFragment(
                            text=value, line_number=row_number, field_name=field_name
                        )
