from __future__ import annotations

from pathlib import Path

from sentinelscan.models import ScanResult


def write_json_report(result: ScanResult, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / "sentinelscan-report.json"
    report_path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
    return report_path
