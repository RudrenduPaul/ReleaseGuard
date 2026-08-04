"""Shared types for ReleaseGuard.

Every dataclass here maps directly to a JSON shape returned by `--json`
on the CLI or by the matching MCP tool -- keep `to_dict()` the single
source of truth for that shape so the human table output and the
machine-readable output can never drift apart.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class RedactionStrategy(str, Enum):
    MASK = "mask"
    HASH = "hash"
    REMOVE = "remove"


@dataclass(frozen=True)
class Finding:
    """One detected PII/secret entity, located inside one source file."""

    file_path: str
    entity_type: str
    start: int
    end: int
    score: float
    text_preview: str
    line_number: int | None = None
    field_name: str | None = None
    detector: str = "presidio"

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_path": self.file_path,
            "entity_type": self.entity_type,
            "start": self.start,
            "end": self.end,
            "score": round(self.score, 4),
            "text_preview": self.text_preview,
            "line_number": self.line_number,
            "field_name": self.field_name,
            "detector": self.detector,
        }


@dataclass
class ScanResult:
    """Result of scanning a directory for PII/secrets."""

    root_path: str
    files_scanned: int
    files_skipped: list[str]
    findings: list[Finding] = field(default_factory=list)
    entity_counts: dict[str, int] = field(default_factory=dict)
    detector_name: str = "presidio"
    language: str = "en"

    def to_dict(self) -> dict[str, Any]:
        return {
            "root_path": self.root_path,
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "findings": [f.to_dict() for f in self.findings],
            "entity_counts": self.entity_counts,
            "total_findings": len(self.findings),
            "detector_name": self.detector_name,
            "language": self.language,
        }


@dataclass
class RedactionResult:
    """Result of redacting a directory using a prior ScanResult."""

    source_root: str
    output_root: str
    strategy: str
    files_written: list[str] = field(default_factory=list)
    entities_redacted: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_root": self.source_root,
            "output_root": self.output_root,
            "strategy": self.strategy,
            "files_written": self.files_written,
            "entities_redacted": self.entities_redacted,
            "total_redacted": sum(self.entities_redacted.values()),
        }


@dataclass
class PackageResult:
    """Result of building a release bundle from scan + redaction results."""

    bundle_dir: str
    dataset_card_path: str | None
    model_card_path: str | None
    eu_ai_act_summary_path: str
    source_kind: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "bundle_dir": self.bundle_dir,
            "dataset_card_path": self.dataset_card_path,
            "model_card_path": self.model_card_path,
            "eu_ai_act_summary_path": self.eu_ai_act_summary_path,
            "source_kind": self.source_kind,
        }
