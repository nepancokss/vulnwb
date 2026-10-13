from __future__ import annotations

from http.cookies import SimpleCookie

from sentinelscan.models import Confidence, Finding, Severity

SENSITIVE_NAMES = {"session", "sid", "token", "auth", "jwt"}


def analyze_cookie_headers(target_url: str, set_cookie_headers: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for header in set_cookie_headers:
        cookie = SimpleCookie()
        cookie.load(header)
        for morsel in cookie.values():
            name = morsel.key
            attrs = {
                "secure": bool(morsel["secure"]),
                "httponly": bool(morsel["httponly"]),
                "samesite": morsel["samesite"] or "",
            }
            lower_name = name.lower()
            if any(token in lower_name for token in SENSITIVE_NAMES):
                if not attrs["secure"]:
                    findings.append(
                        Finding(
                            title="Sensitive cookie missing Secure attribute",
                            category="cookies",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.HIGH,
                            target_url=target_url,
                            description=(
                                "A sensitive-looking cookie was set without the Secure attribute."
                            ),
                            evidence={"cookie_name": name, "attributes": attrs},
                            remediation="Set the Secure attribute for sensitive cookies.",
                            references=[
                                "https://owasp.org/www-community/controls/SecureCookieAttribute"
                            ],
                            check_name="cookies",
                        )
                    )
                if not attrs["httponly"]:
                    findings.append(
                        Finding(
                            title="Sensitive cookie missing HttpOnly attribute",
                            category="cookies",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.HIGH,
                            target_url=target_url,
                            description=("A sensitive-looking cookie was set without HttpOnly."),
                            evidence={"cookie_name": name, "attributes": attrs},
                            remediation="Set the HttpOnly attribute for sensitive cookies.",
                            references=["https://owasp.org/www-community/HttpOnly"],
                            check_name="cookies",
                        )
                    )
            if not attrs["samesite"]:
                findings.append(
                    Finding(
                        title="Cookie missing SameSite attribute",
                        category="cookies",
                        severity=Severity.LOW,
                        confidence=Confidence.MEDIUM,
                        target_url=target_url,
                        description="Cookie did not include SameSite.",
                        evidence={"cookie_name": name},
                        remediation=(
                            "Set an explicit SameSite policy suitable for application flows."
                        ),
                        references=[
                            "https://developer.mozilla.org/docs/Web/HTTP/"
                            "Headers/Set-Cookie/SameSite"
                        ],
                        check_name="cookies",
                    )
                )
    return findings
