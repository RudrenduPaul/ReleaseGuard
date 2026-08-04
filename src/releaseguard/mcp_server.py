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

from typing import Any

from mcp.server import MCPServer

from releaseguard.types import RedactionStrategy


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
        from releaseguard.detectors import get_detector
        from releaseguard.scanner import scan_directory as _scan_directory

        detector = get_detector(
            "presidio", spacy_model=spacy_model, score_threshold=score_threshold
        )
        return _scan_directory(path, detector).to_dict()

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
        from releaseguard.detectors import get_detector
        from releaseguard.redactor import redact_directory as _redact_directory
        from releaseguard.scanner import scan_directory as _scan_directory

        detector = get_detector("presidio")
        scan_result = _scan_directory(path, detector)
        result = _redact_directory(
            scan_result, output, strategy=RedactionStrategy(strategy), overwrite=overwrite
        )
        return result.to_dict()

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
                scan_result, redacted_dir, strategy=RedactionStrategy(strategy), overwrite=True
            )

        result = build_release_bundle(
            scan_result, output, redaction_result=redaction_result, source_kind=kind
        )
        return result.to_dict()

    return app


def run_server() -> None:
    app = build_app()
    app.run()
