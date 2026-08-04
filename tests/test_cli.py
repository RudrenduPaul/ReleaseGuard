import json

import pytest
from click.testing import CliRunner

from releaseguard.cli import main


@pytest.fixture
def sample_dir(tmp_path):
    (tmp_path / "notes.txt").write_text("Contact John Smith at john@example.com\n")
    return tmp_path


def test_scan_json_output(sample_dir):
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(sample_dir), "--json", "--score-threshold", "0.1"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["files_scanned"] == 1
    assert payload["total_findings"] >= 1


def test_scan_human_output(sample_dir):
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(sample_dir), "--score-threshold", "0.1"])
    assert result.exit_code == 0, result.output
    assert "Scanned 1 file(s)" in result.output


def test_redact_writes_output_dir(sample_dir, tmp_path):
    output = tmp_path / "redacted"
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["redact", str(sample_dir), "--output", str(output), "--json", "--score-threshold", "0.1"],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["output_root"] == str(output)
    assert (output / "notes.txt").exists()


def test_redact_accepts_entities_filter(sample_dir, tmp_path):
    output = tmp_path / "redacted"
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "redact",
            str(sample_dir),
            "--output",
            str(output),
            "--json",
            "--score-threshold",
            "0.1",
            "--entities",
            "EMAIL_ADDRESS",
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert set(payload["entities_redacted"].keys()) <= {"EMAIL_ADDRESS"}


def test_redact_refuses_nonempty_output_without_overwrite(sample_dir, tmp_path):
    output = tmp_path / "redacted"
    output.mkdir()
    (output / "existing.txt").write_text("keep me\n")

    runner = CliRunner()
    result = runner.invoke(main, ["redact", str(sample_dir), "--output", str(output)])
    assert result.exit_code != 0


def test_package_writes_bundle(sample_dir, tmp_path):
    output = tmp_path / "bundle"
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "package",
            str(sample_dir),
            "--output",
            str(output),
            "--json",
            "--score-threshold",
            "0.1",
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["dataset_card_path"] is not None
    assert (output / "eu-ai-act-training-summary.md").exists()


def test_package_accepts_entities_filter(sample_dir, tmp_path):
    output = tmp_path / "bundle"
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "package",
            str(sample_dir),
            "--output",
            str(output),
            "--json",
            "--score-threshold",
            "0.1",
            "--entities",
            "EMAIL_ADDRESS",
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert set(payload["scan"]["entity_counts"].keys()) <= {"EMAIL_ADDRESS"}


def test_mcp_command_without_extra_fails_clearly(monkeypatch, sample_dir):
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "releaseguard.mcp_server":
            raise ImportError("mcp not installed")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    runner = CliRunner()
    result = runner.invoke(main, ["mcp"])
    assert result.exit_code != 0
    assert "mcp" in result.output.lower()


def test_version_flag():
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "releaseguard" in result.output
