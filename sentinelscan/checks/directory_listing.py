from __future__ import annotations

from sentinelscan.models import Confidence, Finding, Severity

LISTING_MARKERS = ("<title>index of", "directory listing for", "parent directory")


def analyze_directory_listing(
    target_url: str,
    path: str,
    status_code: int,
    body: str,
) -> list[Finding]:
    if status_code != 200:
        return []
    body_lower = body.lower()
    if any(marker in body_lower for marker in LISTING_MARKERS):
        return [
            Finding(
                title="Potential directory listing exposed",
                category="directory_listing",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                target_url=f"{target_url.rstrip('/')}{path}",
                description=(
                    "Response contains markers commonly associated with directory indexing."
                ),
                evidence={"path": path},
                remediation="Disable autoindex/directory browsing for public paths.",
                references=[],
                check_name="directory_listing",
            )
        ]
    return []
