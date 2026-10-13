from __future__ import annotations

import socket
import ssl
from datetime import UTC, datetime
from urllib.parse import urlparse

from sentinelscan.models import Confidence, Finding, Severity


def inspect_tls(target_url: str, timeout: float = 5.0) -> list[Finding]:
    parsed = urlparse(target_url)
    if parsed.scheme != "https" or not parsed.hostname:
        return []
    findings: list[Finding] = []
    ctx = ssl.create_default_context()
    try:
        address = (parsed.hostname, parsed.port or 443)
        with socket.create_connection(address, timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=parsed.hostname) as tls_sock:
                cert = tls_sock.getpeercert()
    except ssl.SSLCertVerificationError as exc:
        findings.append(
            Finding(
                title="TLS certificate verification failed",
                category="tls",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                target_url=target_url,
                description="Certificate verification failed.",
                evidence={"error": str(exc)},
                remediation="Deploy a valid certificate chain with correct hostname matching.",
                references=[
                    "https://cheatsheetseries.owasp.org/cheatsheets/"
                    "Transport_Layer_Security_Cheat_Sheet.html"
                ],
                check_name="tls",
            )
        )
        return findings
    except OSError as exc:
        findings.append(
            Finding(
                title="TLS inspection could not be completed",
                category="tls",
                severity=Severity.INFORMATIONAL,
                confidence=Confidence.LOW,
                target_url=target_url,
                description="Unable to complete active TLS inspection.",
                evidence={"error": str(exc)},
                remediation="Validate network reachability and TLS configuration manually.",
                references=[],
                check_name="tls",
            )
        )
        return findings

    not_after = cert.get("notAfter")
    if not not_after:
        return findings
    try:
        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
    except ValueError:
        return findings
    remaining = (expiry - datetime.now(UTC)).days
    if remaining < 0:
        findings.append(
            Finding(
                title="TLS certificate expired",
                category="tls",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                target_url=target_url,
                description="Server certificate is expired.",
                evidence={"expiry": expiry.isoformat()},
                remediation="Renew and deploy a valid certificate immediately.",
                references=[],
                check_name="tls",
            )
        )
    elif remaining <= 30:
        findings.append(
            Finding(
                title="TLS certificate nearing expiration",
                category="tls",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                target_url=target_url,
                description="Server certificate expires soon.",
                evidence={"expiry": expiry.isoformat(), "days_remaining": remaining},
                remediation="Plan certificate renewal before expiry.",
                references=[],
                check_name="tls",
            )
        )
    return findings
