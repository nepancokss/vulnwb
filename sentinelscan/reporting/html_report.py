from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from sentinelscan.models import ScanResult


def _env(template_dir: Path) -> Environment:
    return Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(enabled_extensions=("html",)),
    )


def write_html_report(result: ScanResult, output_dir: Path, template_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    template = _env(template_dir).get_template("report.html")
    html = template.render(result=result)
    path = output_dir / "sentinelscan-report.html"
    path.write_text(html, encoding="utf-8")
    return path
