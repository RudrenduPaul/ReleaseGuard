"""Build a public-release bundle from scan (+ optional redaction) results.

This is `releaseguard package`'s core logic: the one command that turns a
scan into a dataset card, a model card (when requested), and an EU AI Act
Art. 53(1)(d) training-data-summary template -- all populated from the same
scan/redaction results, never from separately hand-typed claims.

The compliance-template surface is deliberately a small, explicit registry
(`COMPLIANCE_TEMPLATES` below) rather than a hardcoded single call into
`eu_ai_act.generate_eu_ai_act_summary`: `eu_ai_act.py` is the only real
target in v0.1, but a second jurisdiction is a plausible future addition,
gated on real user demand rather than built speculatively (see
CONTRIBUTING.md). A registry entry is a scoped addition when that happens,
not a rewrite of this function.
"""

from __future__ import annotations

import os
from collections.abc import Callable

from releaseguard.dataset_card import generate_dataset_card
from releaseguard.eu_ai_act import generate_eu_ai_act_summary
from releaseguard.model_card import generate_model_card
from releaseguard.types import PackageResult, RedactionResult, ScanResult

ComplianceTemplateFn = Callable[[ScanResult, RedactionResult | None], str]

COMPLIANCE_TEMPLATES: dict[str, ComplianceTemplateFn] = {
    "eu-ai-act": lambda scan, redaction: generate_eu_ai_act_summary(scan, redaction),
}


def build_release_bundle(
    scan_result: ScanResult,
    output_dir: str,
    redaction_result: RedactionResult | None = None,
    source_kind: str = "dataset",
    compliance_templates: list[str] | None = None,
) -> PackageResult:
    """Write a release bundle (cards + compliance summaries) to `output_dir`.

    `source_kind` is `"dataset"`, `"model"`, or `"both"` -- controls which
    card(s) get generated. `compliance_templates` defaults to every
    registered template (just `eu-ai-act` in v0.1).
    """
    if source_kind not in {"dataset", "model", "both"}:
        raise ValueError(f"source_kind must be 'dataset', 'model', or 'both', got {source_kind!r}")

    os.makedirs(output_dir, exist_ok=True)

    dataset_card_path: str | None = None
    model_card_path: str | None = None

    if source_kind in {"dataset", "both"}:
        dataset_card_path = os.path.join(output_dir, "README-dataset-card.md")
        with open(dataset_card_path, "w", encoding="utf-8") as f:
            f.write(generate_dataset_card(scan_result, redaction_result))

    if source_kind in {"model", "both"}:
        model_card_path = os.path.join(output_dir, "README-model-card.md")
        with open(model_card_path, "w", encoding="utf-8") as f:
            f.write(generate_model_card(scan_result, redaction_result))

    template_names = compliance_templates or list(COMPLIANCE_TEMPLATES.keys())
    eu_ai_act_path = os.path.join(output_dir, "eu-ai-act-training-summary.md")
    for template_name in template_names:
        if template_name not in COMPLIANCE_TEMPLATES:
            raise ValueError(
                f"Unknown compliance template: {template_name!r}. "
                f"Available: {sorted(COMPLIANCE_TEMPLATES)}"
            )
        generator = COMPLIANCE_TEMPLATES[template_name]
        content = generator(scan_result, redaction_result)
        # v0.1 ships exactly one template, so it always writes to the fixed
        # eu-ai-act path above; a second template would get its own
        # `{template_name}-summary.md` file here without touching this loop.
        if template_name == "eu-ai-act":
            with open(eu_ai_act_path, "w", encoding="utf-8") as f:
                f.write(content)

    return PackageResult(
        bundle_dir=output_dir,
        dataset_card_path=dataset_card_path,
        model_card_path=model_card_path,
        eu_ai_act_summary_path=eu_ai_act_path,
        source_kind=source_kind,
    )
