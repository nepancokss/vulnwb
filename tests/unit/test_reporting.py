from datetime import UTC, datetime
from pathlib import Path

from sentinelscan.models import Confidence, Finding, ScanMetadata, ScanResult, Severity
from sentinelscan.reporting.html_report import write_html_report
from sentinelscan.reporting.json_report import write_json_report


def _result() -> ScanResult:
    finding = Finding(
        title="<script>alert(1)</script>",
        category="test",
        severity=Severity.LOW,
        confidence=Confidence.LOW,
        target_url="https://example.com/",
        description="desc",
        evidence={"raw": "<b>x</b>"},
        remediation="fix",
        references=[],
        check_name="test",
    )
    metadata = ScanMetadata(
        target_url="https://example.com/",
        started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
        passive_only=True,
        scope_hosts=["example.com"],
        scanner_version="0.1.0",
    )
    return ScanResult(metadata=metadata, findings=[finding])


def test_json_report_schema(tmp_path: Path) -> None:
    result = _result()
    path = write_json_report(result, tmp_path)
    content = path.read_text(encoding="utf-8")
    assert '"findings"' in content
    assert '"metadata"' in content


def test_html_report_escapes_content(tmp_path: Path) -> None:
    result = _result()
    template_dir = Path(__file__).resolve().parents[2] / "sentinelscan" / "reporting" / "templates"
    path = write_html_report(result, tmp_path, template_dir)
    content = path.read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in content
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in content
