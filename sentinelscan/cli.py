from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from sentinelscan import __version__
from sentinelscan.config import AppConfig, load_config
from sentinelscan.reporting import write_html_report, write_json_report
from sentinelscan.scanner import run_scan
from sentinelscan.utils.logging_setup import configure_logging

app = typer.Typer(help="SentinelScan defensive website scanner")
console = Console()


def _load_or_default(config_path: Path | None) -> AppConfig:
    return load_config(config_path) if config_path else AppConfig()


@app.command("version")
def version() -> None:
    console.print(f"SentinelScan {__version__}")


@app.command("validate-scope")
def validate_scope(config: Annotated[Path, typer.Argument(help="Path to config TOML")]) -> None:
    loaded = load_config(config)
    if not loaded.scope.authorized_hosts:
        raise typer.BadParameter("authorized_hosts cannot be empty")
    table = Table(title="Authorized Scope")
    table.add_column("Host")
    for host in loaded.scope.authorized_hosts:
        table.add_row(host)
    console.print(table)


@app.command("scan")
def scan(
    target: Annotated[str, typer.Argument(help="Target URL")],
    confirm_authorized: Annotated[
        bool,
        typer.Option(
            "--confirm-authorized",
            help="Confirm authorization to scan target",
        ),
    ] = False,
    config: Annotated[
        Path | None,
        typer.Option("--config", help="Path to configuration TOML"),
    ] = None,
    output: Annotated[
        Path,
        typer.Option("--output", help="Report output directory"),
    ] = Path("reports"),
    format: Annotated[
        str,
        typer.Option("--format", help="Comma separated: html,json"),
    ] = "html,json",
    timeout: Annotated[
        float | None,
        typer.Option("--timeout", help="Request timeout seconds"),
    ] = None,
    max_concurrency: Annotated[int | None, typer.Option("--max-concurrency")] = None,
    rate_limit: Annotated[float | None, typer.Option("--rate-limit")] = None,
    max_pages: Annotated[int | None, typer.Option("--max-pages")] = None,
    verbose: Annotated[bool, typer.Option("--verbose")] = False,
    passive_only: Annotated[bool, typer.Option("--passive-only")] = True,
) -> None:
    if not confirm_authorized:
        raise typer.BadParameter("--confirm-authorized is required for safety")

    app_config = _load_or_default(config)
    if timeout is not None:
        app_config.limits.timeout_seconds = timeout
    if max_concurrency is not None:
        app_config.limits.max_concurrency = max_concurrency
    if rate_limit is not None:
        app_config.limits.rate_limit_per_host = rate_limit
    if max_pages is not None:
        app_config.limits.max_pages = max_pages
    app_config.checks.passive_only = passive_only

    configure_logging(output / "logs", verbose=verbose)

    result = asyncio.run(run_scan(target, app_config))

    template_dir = Path(__file__).resolve().parent / "reporting" / "templates"
    outputs: list[Path] = []
    formats = {item.strip().lower() for item in format.split(",") if item.strip()}
    if "json" in formats:
        outputs.append(write_json_report(result, output))
    if "html" in formats:
        outputs.append(write_html_report(result, output, template_dir))

    console.print("Scan complete")
    for path in outputs:
        console.print(f"- {path}")


if __name__ == "__main__":
    app()
