"""Phase 2 tests for CycloneDX 1.6 CBOM, SARIF 2.1.0, Terminal, and Typer CLI."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from cbom_guard.cli import app
from cbom_guard.reporters.cyclonedx import generate_cyclonedx_cbom, validate_cyclonedx_cbom
from cbom_guard.reporters.html import generate_html_report
from cbom_guard.reporters.sarif import generate_sarif
from cbom_guard.scanner.workspace import scan_path

FIXTURES = Path(__file__).parent / "fixtures"
runner = CliRunner()


def test_cyclonedx_16_cbom_validates_against_official_schema() -> None:
    result = scan_path(FIXTURES)
    cbom_json = generate_cyclonedx_cbom(result)
    errors = validate_cyclonedx_cbom(cbom_json)
    assert errors == [], f"CycloneDX 1.6 validation errors: {errors}"

    data = json.loads(cbom_json)
    assert data["bomFormat"] == "CycloneDX"
    assert data["specVersion"] == "1.6"
    crypto_assets = [c for c in data["components"] if c["type"] == "cryptographic-asset"]
    assert len(crypto_assets) == len(result.findings)
    assert any(
        c["cryptoProperties"]["assetType"] == "certificate" for c in crypto_assets
    )
    assert any(
        c["cryptoProperties"]["assetType"] == "algorithm" for c in crypto_assets
    )
    assert len(data.get("vulnerabilities", [])) > 0


def test_sarif_210_output_structure() -> None:
    result = scan_path(FIXTURES)
    sarif_str = generate_sarif(result, base_path=str(FIXTURES))
    sarif_doc = json.loads(sarif_str)

    assert sarif_doc["version"] == "2.1.0"
    assert len(sarif_doc["runs"]) == 1
    run = sarif_doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "cbom-guard"
    assert len(run["tool"]["driver"]["rules"]) > 0
    assert len(run["results"]) == len(result.findings)

    first = run["results"][0]
    loc = first["locations"][0]["physicalLocation"]
    assert loc["region"]["startLine"] >= 1
    assert loc["region"]["startColumn"] >= 1


def test_cli_scan_cbom_sarif_and_list_rules(tmp_path: Path) -> None:
    cbom_file = tmp_path / "out.cbom.json"
    sarif_file = tmp_path / "out.sarif"

    # Fail-on critical should exit 1 on vulnerable fixtures
    res_fail = runner.invoke(
        app,
        [
            "scan",
            str(FIXTURES / "python" / "vulnerable_crypto.py"),
            "--cbom-out",
            str(cbom_file),
            "--sarif-out",
            str(sarif_file),
            "--fail-on",
            "critical",
        ],
    )
    assert res_fail.exit_code == 1
    assert cbom_file.exists()
    assert sarif_file.exists()

    # Safe fixture with --fail-on critical should exit 0
    res_safe = runner.invoke(
        app,
        ["scan", str(FIXTURES / "python" / "safe_crypto.py"), "--fail-on", "critical"],
    )
    assert res_safe.exit_code == 0

    # list-rules command
    res_rules = runner.invoke(app, ["list-rules", "--language", "python"])
    assert res_rules.exit_code == 0
    assert "PY-CRYPTO-001" in res_rules.stdout


def test_cli_version_json_github_output_and_missing_path(tmp_path: Path) -> None:
    res_ver = runner.invoke(app, ["--version"])
    assert res_ver.exit_code == 0
    assert "cbom-guard" in res_ver.stdout

    gh_out = tmp_path / "github_output.txt"
    res_json = runner.invoke(
        app,
        [
            "scan",
            str(FIXTURES / "python" / "vulnerable_crypto.py"),
            "--json",
            "--quiet",
            "--github-output",
            str(gh_out),
            "--fail-on",
            "none",
        ],
    )
    assert res_json.exit_code == 0
    parsed = json.loads(res_json.stdout)
    assert parsed["files_scanned"] == 1
    assert len(parsed["findings"]) > 0
    gh_text = gh_out.read_text(encoding="utf-8")
    assert "critical-count=" in gh_text
    assert "warning-count=" in gh_text

    res_missing = runner.invoke(app, ["scan", str(tmp_path / "does_not_exist")])
    assert res_missing.exit_code == 2


def test_html_dashboard_reporter_and_cli(tmp_path: Path) -> None:
    result = scan_path(FIXTURES)
    html_str = generate_html_report(result)
    assert '<meta name="color-scheme" content="light dark">' in html_str
    assert 'role="region"' in html_str
    assert "X.509 Certificate Inventory" in html_str
    assert "PY-CRYPTO-001" in html_str

    html_file = tmp_path / "report.html"
    res = runner.invoke(
        app,
        [
            "scan",
            str(FIXTURES / "python" / "vulnerable_crypto.py"),
            "--html-out",
            str(html_file),
            "--quiet",
            "--fail-on",
            "none",
        ],
    )
    assert res.exit_code == 0
    assert html_file.exists()
    assert "cbom-guard" in html_file.read_text(encoding="utf-8")
