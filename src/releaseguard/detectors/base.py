"""The detector interface every backend implements."""

from __future__ import annotations

from abc import ABC, abstractmethod

from releaseguard.types import Finding


class PIIDetector(ABC):
    """A backend that finds PII/secret entities inside a text string.

    Implementations do not know about files, directories, or file formats --
    `scanner.py` owns that concern and calls `analyze()` once per text
    fragment it has already extracted (a cell value, a document line, a
    field). This keeps a detector implementation reusable against any
    future file reader without either side depending on the other.
    """

    name: str

    @abstractmethod
    def analyze(self, text: str, language: str = "en") -> list[Finding]:
        """Return findings for one text fragment.

        `Finding.file_path`, `line_number`, and `field_name` are left unset
        here (empty string / None) -- the caller (scanner.py) fills those in
        with the fragment's real location once this returns, since the
        detector itself only sees the fragment's text.
        """
        raise NotImplementedError
