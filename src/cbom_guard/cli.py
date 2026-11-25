"""Typer CLI for cbom-guard."""

from __future__ import annotations

import os
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from cbom_guard import __version__
from cbom_guard.reporters.cyclonedx import generate_cyclonedx_cbom, validate_cyclonedx_cbom
from cbom_guard.reporters.github_pr import post_pr_review_comments
from cbom_guard.reporters.html import generate_html_report
from cbom_guard.reporters.sarif import generate_sarif
from cbom_guard.reporters.terminal import render_terminal_report
from cbom_guard.scanner.rule_engine import RuleEngine
from cbom_guard.scanner.workspace import scan_path

app = typer.Typer(
    name="cbom-guard",
    help="Post-Quantum Cryptography (PQC) code scanner, CycloneDX 1.6 CBOM & SARIF 2.1.0 generator.",
    no_args_is_help=True,
)
console = Console()


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"cbom-guard {__version__}")
        raise typer.Exit(code=0)


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        help="Show cbom-guard version and exit.",
        callback=_version_callback,
        is_eager=True,
    ),
) -> None:
    """cbom-guard CLI."""


@app.command()
def scan(
    path: Path = typer.Argument(Path("."), help="File or directory to scan."),
    cbom_out: Path | None = typer.Option(None, "--cbom-out", help="Write CycloneDX 1.6 CBOM JSON."),
    sarif_out: Path | None = typer.Option(None, "--sarif-out", help="Write SARIF 2.1.0 JSON."),
    html_out: Path | None = typer.Option(
        None, "--html-out", help="Write self-contained HTML PQC readiness dashboard."
    ),
    rules_dir: Path | None = typer.Option(None, "--rules-dir", help="Custom YAML rules directory."),
    fail_on: str = typer.Option(
        "critical",
        "--fail-on",
        help="Exit non-zero on findings at or above threshold: critical | warning | none.",
    ),
    json_out: bool = typer.Option(False, "--json", help="Print scan results as JSON to stdout."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress terminal table output."),
    github_output: Path | None = typer.Option(
        None,
        "--github-output",
        help="Append critical-count and warning-count to a GitHub Actions output file.",
    ),
) -> None:
    """Scan source code and X.509 certificates for PQC readiness."""
    if not path.exists():
        console.print(f"[bold red]Error:[/bold red] Path does not exist: {path}")
        raise typer.Exit(code=2)

    result = scan_path(path, rules_dir=rules_dir)

    if json_out:
        typer.echo(result.model_dump_json(indent=2))
    elif not quiet:
        render_terminal_report(result, console=console)

    if cbom_out is not None:
        cbom_json = generate_cyclonedx_cbom(result)
        cbom_out.parent.mkdir(parents=True, exist_ok=True)
        cbom_out.write_text(cbom_json, encoding="utf-8")
        if not quiet and not json_out:
            console.print(f"[green]Wrote CycloneDX 1.6 CBOM to {cbom_out}[/green]")

    if sarif_out is not None:
        sarif_json = generate_sarif(result, base_path=str(path if path.is_dir() else path.parent))
        sarif_out.parent.mkdir(parents=True, exist_ok=True)
        sarif_out.write_text(sarif_json, encoding="utf-8")
        if not quiet and not json_out:
            console.print(f"[green]Wrote SARIF 2.1.0 report to {sarif_out}[/green]")

    if html_out is not None:
        html_doc = generate_html_report(result)
        html_out.parent.mkdir(parents=True, exist_ok=True)
        html_out.write_text(html_doc, encoding="utf-8")
        if not quiet and not json_out:
            console.print(f"[green]Wrote HTML dashboard report to {html_out}[/green]")

    if github_output is not None:
        with github_output.open("a", encoding="utf-8") as fh:
            fh.write(f"critical-count={result.critical_count}\n")
            fh.write(f"warning-count={result.warning_count}\n")

    try:
        should_fail = result.should_fail(fail_on)
    except ValueError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(code=2) from exc

    if should_fail:
        raise typer.Exit(code=1)


@app.command()
def cbom(
    path: Path = typer.Argument(Path("."), help="File or directory to scan."),
    output: Path = typer.Option(Path("cbom.json"), "--output", "-o", help="Output CBOM JSON file."),
    validate: bool = typer.Option(
        True, "--validate/--no-validate", help="Validate against CycloneDX 1.6 schema."
    ),
    rules_dir: Path | None = typer.Option(None, "--rules-dir", help="Custom YAML rules directory."),
) -> None:
    """Generate a CycloneDX 1.6 Cryptographic Bill of Materials (CBOM)."""
    if not path.exists():
        console.print(f"[bold red]Error:[/bold red] Path does not exist: {path}")
        raise typer.Exit(code=2)

    result = scan_path(path, rules_dir=rules_dir)
    cbom_json = generate_cyclonedx_cbom(result)

    if validate:
        errors = validate_cyclonedx_cbom(cbom_json)
        if errors:
            console.print(f"[bold red]CycloneDX 1.6 validation failed:[/bold red] {errors}")
            raise typer.Exit(code=1)

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(cbom_json, encoding="utf-8")
    console.print(
        f"[green]Generated valid CycloneDX 1.6 CBOM ({len(result.findings)} assets) -> {output}[/green]"
    )


@app.command()
def sarif(
    path: Path = typer.Argument(Path("."), help="File or directory to scan."),
    output: Path = typer.Option(
        Path("cbom-guard.sarif"), "--output", "-o", help="Output SARIF 2.1.0 file."
    ),
    rules_dir: Path | None = typer.Option(None, "--rules-dir", help="Custom YAML rules directory."),
) -> None:
    """Export findings in SARIF 2.1.0 format for GitHub Code Scanning."""
    if not path.exists():
        console.print(f"[bold red]Error:[/bold red] Path does not exist: {path}")
        raise typer.Exit(code=2)

    result = scan_path(path, rules_dir=rules_dir)
    sarif_json = generate_sarif(result, base_path=str(path if path.is_dir() else path.parent))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(sarif_json, encoding="utf-8")
    console.print(
        f"[green]Generated SARIF 2.1.0 report ({len(result.findings)} results) -> {output}[/green]"
    )


@app.command("pr-comment")
def pr_comment(
    path: Path = typer.Argument(Path("."), help="Repository root path to scan."),
    repo: str = typer.Option(..., "--repo", help="GitHub repository in 'owner/name' format."),
    pr_number: int = typer.Option(..., "--pr", help="Pull Request number."),
    token: str | None = typer.Option(
        None, "--token", help="GitHub token (defaults to GITHUB_TOKEN)."
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Build review payload without posting."),
    rules_dir: Path | None = typer.Option(None, "--rules-dir", help="Custom YAML rules directory."),
) -> None:
    """Post deduplicated inline PQC remediation comments on a GitHub Pull Request."""
    resolved_token = token or os.environ.get("GITHUB_TOKEN", "")
    if not resolved_token:
        console.print(
            "[bold red]Error:[/bold red] --token or GITHUB_TOKEN environment variable is required."
        )
        raise typer.Exit(code=2)

    result = scan_path(path, rules_dir=rules_dir)
    summary = post_pr_review_comments(
        scan_result=result,
        repo=repo,
        pr_number=pr_number,
        token=resolved_token,
        repo_root=path,
        dry_run=dry_run,
    )
    console.print(
        f"[green]PR #{pr_number} review complete:[/green] "
        f"posted={summary['posted_count']}, pending={summary['pending_count']}, "
        f"skipped_duplicates={summary['skipped_duplicates']}"
    )


@app.command("list-rules")
def list_rules(
    language: str | None = typer.Option(None, "--language", "-l", help="Filter by language."),
    rules_dir: Path | None = typer.Option(None, "--rules-dir", help="Custom YAML rules directory."),
) -> None:
    """List all loaded cryptographic detection rules."""
    rules = (
        RuleEngine.load_rules_from_dir(rules_dir)
        if rules_dir
        else RuleEngine.load_default_rules()
    )
    if language:
        rules = [r for r in rules if r.language.value.lower() == language.lower()]

    table = Table(title=f"cbom-guard Rules ({len(rules)} loaded)", header_style="bold magenta")
    table.add_column("ID", no_wrap=True)
    table.add_column("Lang", no_wrap=True)
    table.add_column("Algorithm", no_wrap=True)
    table.add_column("Threat", no_wrap=True)
    table.add_column("Risk", no_wrap=True)
    table.add_column("Hybrid-PQC Target", ratio=1)

    for r in rules:
        table.add_row(
            r.id,
            r.language.value,
            r.algorithm,
            r.quantum_vulnerability.value.upper(),
            r.risk_level.value.upper(),
            r.remediation.hybrid_pqc_target,
        )
    console.print(table)
