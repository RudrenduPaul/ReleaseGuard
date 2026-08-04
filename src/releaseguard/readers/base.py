"""The file reader interface every format implementation follows."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass


@dataclass(frozen=True)
class TextFragment:
    """One unit of extractable text inside a file, plus where it came from.

    For a plain-text file this is one line. For a structured file (CSV,
    JSON) this is one cell/field value -- `field_name` and `line_number`
    carry enough location context for `scanner.py` to build a precise
    `Finding` without the reader needing to know anything about detection.
    """

    text: str
    line_number: int | None = None
    field_name: str | None = None


def unique_field_names(header: list[str]) -> list[str]:
    """Disambiguate a CSV header row so duplicate column names never collide.

    `csv.DictReader`/`DictWriter` silently collapse duplicate header names
    into one dict key, keeping only the last column's value -- a CSV with
    header `email,note,email` reads the *first* `email` column's value as
    unreachable (never scanned) and, on write-back, duplicates the
    *second* column's redacted value into both `email` slots. Confirmed
    during an independent security review. This function is used by both
    `CsvReader` (read) and `redactor.py`'s CSV writer (write-back) so the
    same field name always identifies the same physical column on both
    sides -- true duplicates get an explicit `[index]` suffix
    (`email[1]`, `email[2]`); a header that appears only once is returned
    unchanged, so this is a no-op for the common case.
    """
    counts: dict[str, int] = {}
    for name in header:
        counts[name] = counts.get(name, 0) + 1

    seen: dict[str, int] = {}
    result: list[str] = []
    for name in header:
        if counts[name] > 1:
            seen[name] = seen.get(name, 0) + 1
            result.append(f"{name}[{seen[name]}]")
        else:
            result.append(name)
    return result


class FileReader(ABC):
    """A format-specific reader that yields scannable text fragments."""

    format_name: str

    @abstractmethod
    def matches(self, path: str) -> bool:
        """Return True if this reader should handle the given file path."""
        raise NotImplementedError

    @abstractmethod
    def read_fragments(self, path: str) -> Iterator[TextFragment]:
        """Yield every scannable text fragment in the file at `path`."""
        raise NotImplementedError
