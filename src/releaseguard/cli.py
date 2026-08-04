"""ReleaseGuard CLI entry point."""

from __future__ import annotations

import json
import sys

import click

from releaseguard import __version__
from releaseguard.types import RedactionStrategy


@click.group()
@click.version_option(version=__version__, prog_name="releaseguard")
def main() -> None:
    """Scan, redact, and package a dataset/model directory for public release.

    ReleaseGuard is a packaging layer on top of Presidio (originally a
    Microsoft project, now maintained by data-privacy-stack) -- it does
    not detect PII independently of Presidio. See the README's "What
    ReleaseGuard is not" section.
    """


@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option(
    "--spacy-model",
    default=None,
    help="spaCy model Presidio should use (default: en_core_web_sm, or $RELEASEGUARD_SPACY_MODEL).",
)
@click.option(
    "--score-threshold",
    default=0.35,
    show_default=True,
    type=float,
    help="Minimum Presidio confidence score to report a finding.",
)
@click.option(
    "--entities",
    default=None,
    help="Comma-separated list of entity types to look for (default: all Presidio recognizers).",
)
@click.option("--json", "as_json", is_flag=True, help="Machine-readable JSON output.")
def scan(
    path: str,
    spacy_model: str | None,
    score_threshold: float,
    entities: str | None,
    as_json: bool,
) -> None:
    """Scan PATH (a file or directory) for PII and secrets using Presidio."""
    from releaseguard.detectors import get_detector
    from releaseguard.scanner import scan_directory

    entity_list = [e.strip() for e in entities.split(",")] if entities else None
    detector = get_detector(
        "presidio", spacy_model=spacy_model, score_threshold=score_threshold, entities=entity_list
    )
    result = scan_directory(path, detector)

    if as_json:
        click.echo(json.dumps(result.to_dict(), indent=2))
        return

    click.echo(f"Scanned {result.files_scanned} file(s) under {result.root_path}")
    if result.files_skipped:
        click.echo(f"Skipped {len(result.files_skipped)} file(s) with no matching reader")
    click.echo(f"Total findings: {len(result.findings)}")
    if result.entity_counts:
        click.echo("")
        click.echo(f"{'entity type':<28}{'count'}")
        for entity_type, count in sorted(result.entity_counts.items(), key=lambda kv: -kv[1]):
            click.echo(f"{entity_type:<28}{count}")
    else:
        click.echo("No PII/secret entities found at the configured score threshold.")


@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option(
    "--output",
    "-o",
    required=True,
    type=click.Path(),
    help="Directory to write the redacted copy to.",
)
@click.option(
    "--strategy",
    type=click.Choice([s.value for s in RedactionStrategy]),
    default=RedactionStrategy.MASK.value,
    show_default=True,
)
@click.option(
    "--overwrite", is_flag=True, help="Allow writing into a non-empty --output directory."
)
@click.option("--spacy-model", default=None)
@click.option("--score-threshold", default=0.35, show_default=True, type=float)
@click.option("--json", "as_json", is_flag=True)
def redact(
    path: str,
    output: str,
    strategy: str,
    overwrite: bool,
    spacy_model: str | None,
    score_threshold: float,
    as_json: bool,
) -> None:
    """Scan PATH and write a redacted copy to --output. Never mutates PATH."""
    from releaseguard.detectors import get_detector
    from releaseguard.redactor import redact_directory
    from releaseguard.scanner import scan_directory

    detector = get_detector("presidio", spacy_model=spacy_model, score_threshold=score_threshold)
    scan_result = scan_directory(path, detector)
    try:
        result = redact_directory(
            scan_result, output, strategy=RedactionStrategy(strategy), overwrite=overwrite
        )
    except FileExistsError as exc:
        click.echo(str(exc), err=True)
        sys.exit(1)

    if as_json:
        click.echo(json.dumps(result.to_dict(), indent=2))
        return

    click.echo(f"Redacted copy written to {result.output_root}")
    click.echo(f"Files written: {len(result.files_written)}")
    total = sum(result.entities_redacted.values())
    click.echo(f"Entities redacted ({strategy}): {total}")
    for entity_type, count in sorted(result.entities_redacted.items(), key=lambda kv: -kv[1]):
        click.echo(f"  {entity_type}: {count}")


@main.command(name="package")
@click.argument("path", type=click.Path(exists=True))
@click.option(
    "--output",
    "-o",
    required=True,
    type=click.Path(),
    help="Directory to write the release bundle to.",
)
@click.option(
    "--kind",
    type=click.Choice(["dataset", "model", "both"]),
    default="dataset",
    show_default=True,
    help="Whether PATH is a dataset directory, a model directory, or both.",
)
@click.option(
    "--redact-first/--no-redact-first",
    default=True,
    show_default=True,
    help="Redact before packaging.",
)
@click.option(
    "--strategy",
    type=click.Choice([s.value for s in RedactionStrategy]),
    default=RedactionStrategy.MASK.value,
    show_default=True,
)
@click.option("--spacy-model", default=None)
@click.option("--score-threshold", default=0.35, show_default=True, type=float)
@click.option("--json", "as_json", is_flag=True)
def package_cmd(
    path: str,
    output: str,
    kind: str,
    redact_first: bool,
    strategy: str,
    spacy_model: str | None,
    score_threshold: float,
    as_json: bool,
) -> None:
    """Scan PATH, optionally redact it, and generate a release bundle in --output.

    The bundle is the core differentiator: a Hugging Face dataset/model card
    plus an EU AI Act Art. 53(1)(d) training-data-summary template, all
    generated from the same scan results in one command.
    """
    from releaseguard.detectors import get_detector
    from releaseguard.packager import build_release_bundle
    from releaseguard.redactor import redact_directory
    from releaseguard.scanner import scan_directory

    detector = get_detector("presidio", spacy_model=spacy_model, score_threshold=score_threshold)
    scan_result = scan_directory(path, detector)

    redaction_result = None
    if redact_first:
        redacted_dir = f"{output.rstrip('/')}-redacted-source"
        redaction_result = redact_directory(
            scan_result, redacted_dir, strategy=RedactionStrategy(strategy), overwrite=True
        )

    result = build_release_bundle(
        scan_result, output, redaction_result=redaction_result, source_kind=kind
    )

    if as_json:
        payload = result.to_dict()
        payload["scan"] = scan_result.to_dict()
        if redaction_result is not None:
            payload["redaction"] = redaction_result.to_dict()
        click.echo(json.dumps(payload, indent=2))
        return

    click.echo(f"Release bundle written to {result.bundle_dir}")
    if result.dataset_card_path:
        click.echo(f"  dataset card: {result.dataset_card_path}")
    if result.model_card_path:
        click.echo(f"  model card:   {result.model_card_path}")
    click.echo(f"  EU AI Act Art. 53(1)(d) summary: {result.eu_ai_act_summary_path}")
    if redaction_result is not None:
        click.echo(f"  redacted source: {redaction_result.output_root}")


@main.command()
def mcp() -> None:
    """Start an MCP server exposing scan/redact/package as agent tools."""
    try:
        from releaseguard.mcp_server import run_server
    except ImportError:
        click.echo(
            'The MCP server requires the "mcp" extra: pip install "releaseguard-cli[mcp]"',
            err=True,
        )
        sys.exit(1)
    run_server()


if __name__ == "__main__":
    main()
