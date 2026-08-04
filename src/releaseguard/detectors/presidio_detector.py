"""Presidio-backed PII detector -- ReleaseGuard's only detection backend.

This wraps `presidio_analyzer.AnalyzerEngine` directly. ReleaseGuard adds
no entity types, no scoring logic, and no accuracy claims of its own --
every entity type detected and every confidence score returned here comes
straight from Presidio's own recognizers. See the README's "What
ReleaseGuard is not" section.

Presidio's `AnalyzerEngine` needs a spaCy language model, which is not a
pip dependency (spaCy models ship as their own installable packages via
`spacy download`, not `pip install`). ReleaseGuard defaults to
`en_core_web_sm` (~13 MB, fast to install, the same model Presidio's own
quickstart docs use for getting started) rather than `en_core_web_lg`
(~400 MB, higher accuracy, Presidio's recommendation for production use).
Pass `spacy_model="en_core_web_lg"` (or set `RELEASEGUARD_SPACY_MODEL`,
read by the CLI) to use the larger model once it's installed.
"""

from __future__ import annotations

import os
from typing import Any

from releaseguard.detectors.base import PIIDetector
from releaseguard.types import Finding

DEFAULT_SPACY_MODEL = "en_core_web_sm"


class PresidioDetector(PIIDetector):
    name = "presidio"

    def __init__(
        self,
        spacy_model: str | None = None,
        score_threshold: float = 0.35,
        entities: list[str] | None = None,
    ) -> None:
        # Imported lazily so `releaseguard --help` and every non-scanning
        # command stay fast -- presidio_analyzer pulls in spaCy, which is
        # a multi-second import on a cold process.
        from presidio_analyzer import AnalyzerEngine
        from presidio_analyzer.nlp_engine import NlpEngineProvider

        model = spacy_model or os.environ.get("RELEASEGUARD_SPACY_MODEL", DEFAULT_SPACY_MODEL)
        self.spacy_model = model
        self.score_threshold = score_threshold
        self.entities = entities

        nlp_configuration = {
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": model}],
        }
        provider = NlpEngineProvider(nlp_configuration=nlp_configuration)
        nlp_engine = provider.create_engine()
        self._engine = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["en"])

    def analyze(self, text: str, language: str = "en") -> list[Finding]:
        if not text or not text.strip():
            return []

        kwargs: dict[str, Any] = {"score_threshold": self.score_threshold}
        if self.entities:
            kwargs["entities"] = self.entities

        results = self._engine.analyze(text=text, language=language, **kwargs)

        findings = []
        for result in results:
            preview = text[result.start : result.end]
            findings.append(
                Finding(
                    file_path="",
                    entity_type=result.entity_type,
                    start=result.start,
                    end=result.end,
                    score=result.score,
                    text_preview=preview,
                    detector=self.name,
                )
            )
        return findings
