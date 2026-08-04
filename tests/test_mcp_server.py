"""Smoke tests for the MCP server's tool surface.

mcp_server.py is excluded from the coverage gate (see pyproject.toml --
same convention as cli.py: thin wiring around already-tested core logic),
but a registration smoke test still catches a real class of bug: an SDK
upgrade silently renaming the decorator/class this module depends on.
"""

from __future__ import annotations

import asyncio

import pytest

pytest.importorskip("mcp")

from releaseguard.mcp_server import build_app  # noqa: E402


def test_build_app_registers_all_three_tools():
    app = build_app()
    tools = asyncio.run(app.list_tools())
    names = {t.name for t in tools}
    assert names == {"scan_directory_tool", "redact_directory_tool", "package_release_tool"}


def test_scan_directory_tool_returns_the_same_shape_as_the_cli(tmp_path):
    (tmp_path / "notes.txt").write_text("Contact john@example.com\n")
    app = build_app()

    async def _call():
        return await app.call_tool(
            "scan_directory_tool", {"path": str(tmp_path), "score_threshold": 0.1}
        )

    result = asyncio.run(_call())
    payload = result.structured_content
    assert payload["files_scanned"] == 1
    assert payload["entity_counts"]["EMAIL_ADDRESS"] == 1
