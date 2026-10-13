from __future__ import annotations

from urllib.parse import urljoin

from sentinelscan.models import Confidence, Finding, Severity


def summarize_robots_sitemap(base_url: str, path: str, body: str) -> list[Finding]:
    lines = [
        line.strip()
        for line in body.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    discovered = []
    for line in lines:
        lowered = line.lower()
        if lowered.startswith("disallow:") or lowered.startswith("allow:"):
            value = line.split(":", 1)[1].strip()
            if value:
                discovered.append(value)
        if lowered.startswith("sitemap:"):
            discovered.append(line.split(":", 1)[1].strip())

    if not discovered:
        return []

    return [
        Finding(
            title=f"{path.lstrip('/')} entries discovered",
            category="robots_sitemap",
            severity=Severity.INFORMATIONAL,
            confidence=Confidence.HIGH,
            target_url=urljoin(base_url, path),
            description=("robots/sitemap paths were discovered and recorded for manual review."),
            evidence={"paths": discovered[:30]},
            remediation=(
                "Review listed paths for unintended exposure. robots.txt "
                "entries alone are not vulnerabilities."
            ),
            references=[],
            check_name="robots_sitemap",
        )
    ]
