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
        """Scan a dataset/model directory for PII and secrets with Presidio.

        Returns every finding (entity type, file, location, confidence).
        Detection is entirely Presidio's -- this tool does not add its own
        detection logic or accuracy claims.
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
        """Scan a directory and write a redacted copy. Never mutates `path`.

        `strategy` is one of "mask", "hash", "remove".
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
        """Scan, optionally redact, and package a release bundle in one call.

        Produces a Hugging Face dataset/model card and an EU AI Act
        Art. 53(1)(d) training-data-summary template, both generated from
        the scan results. `kind` is "dataset", "model", or "both".
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
