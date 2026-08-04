"""Pluggable file readers -- one interface, one implementation per format.

The domain here genuinely has multiple integration targets: the product
definition names CSV/JSON/JSONL/Parquet and plain text corpora as v0.1
targets, and datasets in the wild show up in more formats than that
(YAML, XML exports, other columnar formats). `FileReader` is the seam that
lets a new format be added as one new module registered in
`DEFAULT_READERS`, without touching `scanner.py`, `redactor.py`, or any
other reader.
"""

from __future__ import annotations

from releaseguard.readers.base import FileReader, TextFragment
from releaseguard.readers.csv_reader import CsvReader
from releaseguard.readers.json_reader import JsonReader
from releaseguard.readers.text_reader import TextReader

DEFAULT_READERS: list[FileReader] = [CsvReader(), JsonReader(), TextReader()]

__all__ = ["FileReader", "TextFragment", "DEFAULT_READERS", "get_reader_for"]


def get_reader_for(path: str, readers: list[FileReader] | None = None) -> FileReader | None:
    """Return the first reader (in registration order) that claims `path`."""
    for reader in readers if readers is not None else DEFAULT_READERS:
        if reader.matches(path):
            return reader
    return None
