"""MCP server: exposes ReleaseGuard as agent-callable tools.

Requires the `mcp` extra (`pip install "releaseguard-cli[mcp]"`). Started via
`releaseguard mcp` (stdio transport), so any MCP-compatible agent runtime can
call scan_directory / redact_directory / package_release directly instead of
shelling out to the CLI and parsing text.

Uses `mcp.server.MCPServer`, the official SDK's current high-level server
class (`mcp` 2.0.0+). Earlier `mcp` 1.x releases exposed the same
`.tool()`/`.run()` pattern under `mcp.server.fastmcp.FastMCP` -- that module
was removed in the 2.0.0 release, confirmed directly against the installed
package rather than assumed from older examples. If a future `mcp` major
version renames this again, this is the one file that needs to change.
"""

from __future__ import annotations

import os
from typing import Any

from mcp.server import MCPServer

from releaseguard.types import RedactionStrategy


def _path_error(path: str) -> dict[str, Any] | None:
    """Mirror the CLI's `click.Path(exists=True)` check.

    The CLI rejects a nonexistent PATH before ever calling into
    `scanner.scan_directory` (exit code 2, "Path does not exist"). The
    internal scan/redact/package functions this MCP server calls directly
    do not perform that check themselves -- a nonexistent directory just
    makes `os.walk` yield nothing, so calling them straight from a tool
    handler silently returns a misleading "0 files scanned, 0 findings"
    success result instead of an error, for the same bad input the CLI
    would refuse outright. Every tool below calls this first so an agent
    never mistakes "path doesn't exist" for "path is clean."
    """
    if not os.path.exists(path):
        return {"error": f"Path '{path}' does not exist.", "error_type": "PathNotFound"}
    return None


def build_app() -> MCPServer:
    app = MCPServer("releaseguard")

    @app.tool()
    def scan_directory_tool(
        path: str,
        spacy_model: str | None = None,
        score_threshold: float = 0.35,
    ) -> dict[str, Any]:
        """Recursively scan a local dataset or model directory for PII and secrets before you publish it.

        Call this before releasing, uploading, or sharing a dataset/model
        directory whenever you need to know what personal data it contains --
        it is the read-only first step agents should take ahead of
        `redact_directory_tool` or `package_release_tool`, and the right
        choice on its own when you only need a report, not a redacted copy.
        Do not call it on directories you do not have read access to, or
        expect it to catch anything beyond what Presidio's own recognizers
        detect (no custom regex or heuristics are layered on top).

        `path` must be a directory (or single file) that already exists on
        disk and is readable by the current process; it walks CSV, JSON/
        JSONL, and plain-text files under it. This call is read-only: it
        never writes, moves, or deletes anything, makes no network requests
        (Presidio and spaCy run entirely locally), and is safe to call
        repeatedly -- re-running it against an unchanged directory returns
        the same findings. On a missing `path`, or any internal failure, it
        returns `{"error": ..., "error_type": ...}` instead of raising or
        crashing the server -- check for an `error` key before reading
        `findings`.

        `spacy_model` selects the spaCy model Presidio's NLP engine uses
        (defaults to `en_core_web_sm`; must already be installed via
        `python -m spacy download <model>`, this tool does not install
        one). `score_threshold` (0.0-1.0, default 0.35) drops any finding
        below that Presidio confidence score -- raise it to cut false
        positives, lower it to widen recall. Example calls:
        `scan_directory_tool(path="./data")`,
        `scan_directory_tool(path="./data", score_threshold=0.5)`,
        `scan_directory_tool(path="./models/card-dir", spacy_model="en_core_web_lg")`.

        Returns a JSON object with `root_path`, `files_scanned`,
        `files_skipped`, `findings` (a list of objects each with
        `file_path`, `entity_type`, `start`/`end` offsets, `score`,
        `text_preview`, `line_number`, `field_name`, `detector`),
        `entity_counts` (per-type totals), `total_findings`,
        `detector_name`, and `language`. For flag-level detail beyond this
        docstring, run the equivalent CLI form: `releaseguard scan --help`.
        """
        if (err := _path_error(path)) is not None:
            return err
        try:
            from releaseguard.detectors import get_detector
            from releaseguard.scanner import scan_directory as _scan_directory

            detector = get_detector(
                "presidio", spacy_model=spacy_model, score_threshold=score_threshold
            )
            return _scan_directory(path, detector).to_dict()
        except Exception as exc:  # never let a tool call crash the server
            return {"error": str(exc), "error_type": type(exc).__name__}

    @app.tool()
    def redact_directory_tool(
        path: str,
        output: str,
        strategy: str = "mask",
        overwrite: bool = False,
    ) -> dict[str, Any]:
        """Scan a directory for PII/secrets with Presidio, then write a redacted copy to a new location.

        Call this once you already know (or expect) a directory contains
        PII and want a sanitized copy you can hand off or publish, without
        touching the original. It runs its own internal scan first (same
        detector as `scan_directory_tool`), so you do not need to call
        `scan_directory_tool` beforehand unless you want to inspect
        findings before deciding to redact. Skip it if you only need a
        report (use `scan_directory_tool`) or if you also want the Hugging
        Face card and EU AI Act summary generated (use
        `package_release_tool`, which redacts as one step of a larger
        bundle).

        `path` must exist and be readable. This tool is mutating but scoped
        to `output` only: it never edits, moves, or deletes anything under
        `path`. Writing fails if `output` already exists and is non-empty,
        unless `overwrite=True` -- pass that deliberately, since it will
        silently overwrite prior contents of `output`. No network calls are
        made; everything runs locally. Not idempotent across repeated calls
        with `overwrite=True` if the source directory changed between runs
        (the redacted copy reflects whatever `path` contains at call time).

        `strategy` controls how each finding is replaced: `"mask"` (default,
        replaces matched text with a placeholder like `<EMAIL_ADDRESS>`),
        `"hash"` (replaces with a deterministic hash of the original value),
        or `"remove"` (deletes the matched span entirely). Example calls:
        `redact_directory_tool(path="./data", output="./data-redacted")`,
        `redact_directory_tool(path="./data", output="./data-redacted", strategy="hash")`,
        `redact_directory_tool(path="./data", output="./data-redacted", overwrite=True)`.

        Returns a JSON object with `source_root`, `output_root`, `strategy`,
        `files_written` (list of paths under `output`), `entities_redacted`
        (per-entity-type counts), and `total_redacted`. On a missing `path`,
        an invalid `strategy`, or a non-empty `output` without
        `overwrite=True`, it returns `{"error": ..., "error_type": ...}`
        instead of raising. See `releaseguard redact --help` for the
        CLI-equivalent flag reference.
        """
        if (err := _path_error(path)) is not None:
            return err
        try:
            from releaseguard.detectors import get_detector
            from releaseguard.redactor import redact_directory as _redact_directory
            from releaseguard.scanner import scan_directory as _scan_directory

            detector = get_detector("presidio")
            scan_result = _scan_directory(path, detector)
            result = _redact_directory(
                scan_result, output, strategy=RedactionStrategy(strategy), overwrite=overwrite
            )
            return result.to_dict()
        except Exception as exc:  # e.g. bad `strategy`, FileExistsError on --output
            return {"error": str(exc), "error_type": type(exc).__name__}

    @app.tool()
    def package_release_tool(
        path: str,
        output: str,
        kind: str = "dataset",
        redact_first: bool = True,
        strategy: str = "mask",
    ) -> dict[str, Any]:
        """Scan a dataset/model directory, redact it, and generate the paperwork needed to publish it, in one call.

        This is the end-to-end tool: use it when the goal is "make this
        directory publishable" rather than just inspecting or redacting it.
        It chains a Presidio scan, an optional redaction pass, and
        generation of a Hugging Face dataset/model card plus an EU AI Act
        Art. 53(1)(d) training-data-summary template, all populated from
        the same scan results so the documents and the redacted copy can
        never disagree. Prefer `scan_directory_tool` alone for a
        read-only report, or `redact_directory_tool` alone when you don't
        need the generated cards. This tool does not detect PII itself --
        detection is entirely Presidio's, unmodified.

        `path` must exist and be readable. This tool is mutating: it writes
        the bundle to `output` (dataset/model card, EU AI Act summary) and,
        when `redact_first=True` (the default), also writes a redacted copy
        to `<output>-redacted-source`, overwriting that directory if it
        already exists. Nothing under `path` itself is ever modified. No
        network calls are made -- scanning, redaction, and document
        generation all run locally. The EU AI Act summary is a draft
        template with scan-derived counts filled in and everything else
        left as an explicit placeholder for a human to complete; it is not
        a compliance guarantee.

        `kind` is `"dataset"` (default), `"model"`, or `"both"`, and picks
        which card template(s) get generated. `redact_first` toggles the
        redaction step (default `True`); `strategy` is `"mask"`, `"hash"`,
        or `"remove"` and only applies when `redact_first=True`. Example
        calls: `package_release_tool(path="./data", output="./release")`,
        `package_release_tool(path="./model", output="./release", kind="model")`,
        `package_release_tool(path="./data", output="./release", redact_first=False)`.

        Returns a JSON object with `bundle_dir`, `dataset_card_path`
        (or null if `kind="model"`), `model_card_path` (or null if
        `kind="dataset"`), `eu_ai_act_summary_path`, and `source_kind`. On a
        missing `path` or any internal failure it returns
        `{"error": ..., "error_type": ...}` instead of raising. See
        `releaseguard package --help` for the CLI-equivalent flag reference.
        """
        if (err := _path_error(path)) is not None:
            return err
        try:
            from releaseguard.detectors import get_detector
            from releaseguard.packager import build_release_bundle
            from releaseguard.redactor import redact_directory as _redact_directory
            from releaseguard.scanner import scan_directory as _scan_directory

            detector = get_detector("presidio")
            scan_result = _scan_directory(path, detector)

            redaction_result = None
            if redact_first:
                redacted_dir = f"{output.rstrip('/')}-redacted-source"
                redaction_result = _redact_directory(
                    scan_result,
                    redacted_dir,
                    strategy=RedactionStrategy(strategy),
                    overwrite=True,
                )

            result = build_release_bundle(
                scan_result, output, redaction_result=redaction_result, source_kind=kind
            )
            return result.to_dict()
        except Exception as exc:
            return {"error": str(exc), "error_type": type(exc).__name__}

    return app


def run_server() -> None:
    app = build_app()
    app.run()
