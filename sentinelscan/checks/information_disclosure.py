from __future__ import annotations

import re

from sentinelscan.models import Confidence, Finding, Severity

SECRET_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|token|password)\s*[:=]\s*[^\s]+"),
]


def redact_sensitive(text: str) -> str:
    redacted = text
    for pattern in SECRET_PATTERNS:
        redacted = pattern.sub("[REDACTED]", redacted)
    return redacted


def analyze_disclosure(target_url: str, path: str, status_code: int, body: str) -> list[Finding]:
    findings: list[Finding] = []
    if status_code >= 400:
        return findings
    preview = redact_sensitive(body[:500])
    lower = body.lower()
    if "traceback" in lower or "exception" in lower:
        findings.append(
            Finding(
                title="Potential diagnostic information disclosure",
                category="information_disclosure",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                target_url=f"{target_url.rstrip('/')}{path}",
                description="Response appears to contain debug or exception output.",
                evidence={"path": path, "preview": preview},
                remediation="Disable verbose error pages in production.",
                references=[],
                check_name="information_disclosure",
            )
        )
    return findings
