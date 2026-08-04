"""Plain-text reader -- .txt, .md, and anything else with no more specific reader."""

from __future__ import annotations

from collections.abc import Iterator

from releaseguard.readers.base import FileReader, TextFragment

TEXT_EXTENSIONS = (".txt", ".md", ".text", ".log")


class TextReader(FileReader):
    format_name = "text"

    def matches(self, path: str) -> bool:
        return path.lower().endswith(TEXT_EXTENSIONS)

    def read_fragments(self, path: str) -> Iterator[TextFragment]:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line_number, line in enumerate(f, start=1):
                stripped = line.rstrip("\n")
                if stripped.strip():
                    yield TextFragment(text=stripped, line_number=line_number)
