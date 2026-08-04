"""Pluggable PII/secret detection backends.

ReleaseGuard's detection layer *is* Presidio -- see `PresidioDetector`, the
only detector shipped in v0.1. This module exists as a real interface
(`PIIDetector`) rather than a hardcoded call into
`presidio_analyzer.AnalyzerEngine` from `scanner.py` directly, because the
domain genuinely has more than one integration target over time: Presidio's
own recognizer registry can be extended with custom recognizers, a future
version may add a secrets-focused detector (API keys, private keys) as a
second backend to run alongside Presidio, and users may want to swap in
their own organization's detection service. A hardcoded single-path call
would need a rewrite for any of those; this interface makes each one a
scoped addition instead. This is not a claim that ReleaseGuard competes
with or improves on Presidio's detection -- it is the seam that keeps
Presidio swappable/extensible without becoming a competing detector itself.
"""

from __future__ import annotations

from releaseguard.detectors.base import PIIDetector
from releaseguard.detectors.presidio_detector import PresidioDetector

__all__ = ["PIIDetector", "PresidioDetector", "get_detector"]


def get_detector(name: str = "presidio", **kwargs: object) -> PIIDetector:
    """Resolve a detector by name. "presidio" is the only backend in v0.1."""
    if name == "presidio":
        return PresidioDetector(**kwargs)  # type: ignore[arg-type]
    raise ValueError(f"Unknown detector backend: {name!r} (only 'presidio' is available in v0.1)")
