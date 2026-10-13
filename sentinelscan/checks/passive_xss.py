from __future__ import annotations

from urllib.parse import parse_qsl, urlparse

from sentinelscan.models import Confidence, Finding, Severity


def analyze_passive_xss(target_url: str, body: str, content_type: str | None) -> list[Finding]:
    if not content_type or "html" not in content_type.lower():
        return []
    parsed = urlparse(target_url)
    findings: list[Finding] = []
    for key, value in parse_qsl(parsed.query, keep_blank_values=False):
        if value and value in body:
            findings.append(
                Finding(
                    title="Potential reflected input observed",
                    category="passive_xss",
                    severity=Severity.LOW,
                    confidence=Confidence.LOW,
                    target_url=target_url,
                    description=(
                        "User-supplied query parameter value appears in HTML response body."
                    ),
                    evidence={"parameter": key, "reflected_value_sample": value[:80]},
                    remediation=(
                        "Contextually encode untrusted input and use output escaping in templates."
                    ),
                    references=["https://owasp.org/www-community/attacks/xss/"],
                    check_name="passive_xss",
                )
            )
    return findings
