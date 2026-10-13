from __future__ import annotations

import re

from sentinelscan.models import Confidence, Finding, Severity

DB_ERROR_PATTERNS = [
    re.compile(r"you have an error in your sql syntax", re.IGNORECASE),
    re.compile(r"postgresql.*error", re.IGNORECASE),
    re.compile(r"sqlite.*error", re.IGNORECASE),
    re.compile(r"odbc.*sql server driver", re.IGNORECASE),
]


def analyze_passive_sqli(target_url: str, body: str) -> list[Finding]:
    for pattern in DB_ERROR_PATTERNS:
        match = pattern.search(body)
        if match:
            return [
                Finding(
                    title="Potential SQL error disclosure",
                    category="passive_sqli",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    target_url=target_url,
                    description=(
                        "Response includes a database error signature that "
                        "may indicate unsafe query handling."
                    ),
                    evidence={"signature": match.group(0)[:120]},
                    remediation="Use parameterized queries and generic error handling.",
                    references=["https://owasp.org/www-community/attacks/SQL_Injection"],
                    check_name="passive_sqli",
                )
            ]
    return []
