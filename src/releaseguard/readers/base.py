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
