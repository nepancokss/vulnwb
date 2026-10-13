from __future__ import annotations

import asyncio
from collections.abc import Iterable
from datetime import UTC, datetime
from urllib.parse import urljoin

from sentinelscan import __version__
from sentinelscan.checks import (
    analyze_cookie_headers,
    analyze_directory_listing,
    analyze_disclosure,
    analyze_passive_sqli,
    analyze_passive_xss,
    analyze_security_headers,
    inspect_tls,
    summarize_robots_sitemap,
)
from sentinelscan.config import AppConfig
from sentinelscan.http_client import HTTPClientError, build_http_client
from sentinelscan.models import Finding, ScanMetadata, ScanResult
from sentinelscan.target_validation import TargetValidationError, validate_target


def _dedupe_findings(findings: Iterable[Finding]) -> list[Finding]:
    unique: dict[tuple[str, str, str, str], Finding] = {}
    for finding in findings:
        key = (finding.title, str(finding.target_url), finding.check_name, str(finding.evidence))
        unique[key] = finding
    return list(unique.values())


async def run_scan(target: str, config: AppConfig) -> ScanResult:
    validated = validate_target(target, config)
    started = datetime.now(UTC)
    findings: list[Finding] = []
    baseline_dns = {validated.hostname: validated.resolved_ips}

    async with build_http_client(config, baseline_dns) as client:
        try:
            main_response = await asyncio.wait_for(
                client.get(validated.normalized_url),
                timeout=config.limits.max_scan_seconds,
            )
        except (HTTPClientError, TimeoutError, TargetValidationError) as exc:
            raise RuntimeError(f"Scan failed safely: {exc}") from exc

        findings.extend(
            analyze_security_headers(validated.normalized_url, dict(main_response.headers))
        )
        findings.extend(
            analyze_cookie_headers(
                validated.normalized_url,
                main_response.headers.get_list("set-cookie"),
            )
        )
        findings.extend(
            inspect_tls(
                validated.normalized_url,
                timeout=config.limits.timeout_seconds,
            )
        )
        text_body = main_response.text[: config.limits.max_response_bytes]
        findings.extend(
            analyze_passive_xss(
                str(main_response.request.url),
                text_body,
                main_response.headers.get("content-type"),
            )
        )
        findings.extend(analyze_passive_sqli(str(main_response.request.url), text_body))

        for path in config.checks.info_paths:
            url = urljoin(validated.normalized_url, path)
            try:
                response = await client.get(
                    url,
                    max_bytes=min(config.limits.max_response_bytes, 200_000),
                )
            except HTTPClientError:
                continue
            body = response.text
            findings.extend(
                analyze_disclosure(
                    validated.normalized_url,
                    path,
                    response.status_code,
                    body,
                )
            )
            if path in {"/robots.txt", "/sitemap.xml"}:
                findings.extend(summarize_robots_sitemap(validated.normalized_url, path, body))

        for path in config.checks.directory_listing_paths:
            url = urljoin(validated.normalized_url, path)
            try:
                response = await client.get(url, max_bytes=200_000)
            except HTTPClientError:
                continue
            findings.extend(
                analyze_directory_listing(
                    validated.normalized_url,
                    path,
                    response.status_code,
                    response.text,
                )
            )

    finished = datetime.now(UTC)
    metadata = ScanMetadata(
        target_url=validated.normalized_url,
        started_at=started,
        finished_at=finished,
        passive_only=config.checks.passive_only,
        scope_hosts=config.scope.authorized_hosts,
        scanner_version=__version__,
        limitations=[
            "Passive checks prioritize safety and may produce false positives.",
            "No authentication bypass, brute-force, or destructive payloads are executed.",
        ],
    )
    return ScanResult(metadata=metadata, findings=_dedupe_findings(findings))
