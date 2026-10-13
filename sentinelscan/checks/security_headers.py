from __future__ import annotations

from urllib.parse import urlparse

from sentinelscan.models import Confidence, Finding, Severity


def analyze_security_headers(target_url: str, headers: dict[str, str]) -> list[Finding]:
    findings: list[Finding] = []
    normalized = {k.lower(): v for k, v in headers.items()}

    if "content-security-policy" not in normalized:
        findings.append(
            Finding(
                title="Missing Content-Security-Policy",
                category="security_headers",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                target_url=target_url,
                description="No CSP header was observed.",
                evidence={"observed_headers": sorted(normalized.keys())},
                remediation=(
                    "Define a restrictive Content-Security-Policy tailored to the application."
                ),
                references=["https://developer.mozilla.org/docs/Web/HTTP/CSP"],
                check_name="security_headers",
            )
        )

    xcto = normalized.get("x-content-type-options", "")
    if "x-content-type-options" not in normalized or xcto.lower() != "nosniff":
        findings.append(
            Finding(
                title="Missing or weak X-Content-Type-Options",
                category="security_headers",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                target_url=target_url,
                description="X-Content-Type-Options should be set to nosniff.",
                evidence={"x-content-type-options": xcto or "missing"},
                remediation="Set X-Content-Type-Options: nosniff.",
                references=[
                    "https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Content-Type-Options"
                ],
                check_name="security_headers",
            )
        )

    if "referrer-policy" not in normalized:
        findings.append(
            Finding(
                title="Missing Referrer-Policy",
                category="security_headers",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                target_url=target_url,
                description="No Referrer-Policy header was observed.",
                evidence={},
                remediation=(
                    "Set Referrer-Policy with a restrictive value, "
                    "such as strict-origin-when-cross-origin."
                ),
                references=["https://developer.mozilla.org/docs/Web/HTTP/Headers/Referrer-Policy"],
                check_name="security_headers",
            )
        )

    scheme = urlparse(target_url).scheme.lower()
    if scheme == "https" and "strict-transport-security" not in normalized:
        findings.append(
            Finding(
                title="Missing Strict-Transport-Security",
                category="security_headers",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                target_url=target_url,
                description="HTTPS is used but HSTS was not observed.",
                evidence={},
                remediation="Enable HSTS once HTTPS deployment is stable.",
                references=[
                    "https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security"
                ],
                check_name="security_headers",
            )
        )

    csp = normalized.get("content-security-policy", "")
    frame_options = normalized.get("x-frame-options", "")
    if "frame-ancestors" not in csp and not frame_options:
        findings.append(
            Finding(
                title="Missing frame embedding protection",
                category="security_headers",
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                target_url=target_url,
                description="Neither CSP frame-ancestors nor X-Frame-Options was present.",
                evidence={},
                remediation="Set CSP frame-ancestors and/or X-Frame-Options.",
                references=["https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Frame-Options"],
                check_name="security_headers",
            )
        )

    return findings
