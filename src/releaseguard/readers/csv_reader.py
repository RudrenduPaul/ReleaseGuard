"""CSV reader -- one fragment per non-empty cell, tagged with its column name."""

from __future__ import annotations

import csv
from collections.abc import Iterator

from releaseguard.readers.base import FileReader, TextFragment, unique_field_names


class CsvReader(FileReader):
    format_name = "csv"

    def matches(self, path: str) -> bool:
        return path.lower().endswith(".csv")

    def read_fragments(self, path: str) -> Iterator[TextFragment]:
        # Reads rows positionally (`csv.reader`) rather than via
        # `csv.DictReader`, specifically so duplicate column names don't
        # collapse into a single dict key and silently lose data -- see
        # `unique_field_names`'s docstring for the concrete bug this
        # avoids.
        with open(path, newline="", encoding="utf-8", errors="replace") as f:
            reader = csv.reader(f)
            try:
                header = next(reader)
            except StopIteration:
                return
            field_names = unique_field_names(header)

            for row_number, row in enumerate(reader, start=2):  # header is line 1
                for field_name, value in zip(field_names, row, strict=False):
                    if value and value.strip():
                        yield TextFragment(
                            text=value, line_number=row_number, field_name=field_name
                        )
