from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlparse

from sentinelscan.config import AppConfig
from sentinelscan.scope import ScopeEnforcer
from sentinelscan.utils.url_utils import normalize_url

BLOCKED_IPS = {"169.254.169.254"}


@dataclass(slots=True)
class ValidatedTarget:
    normalized_url: str
    hostname: str
    resolved_ips: set[str]


class TargetValidationError(ValueError):
    pass


def _is_public_ip(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    if ip in BLOCKED_IPS:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def resolve_public_ips(hostname: str) -> set[str]:
    try:
        infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise TargetValidationError(f"DNS resolution failed for {hostname}") from exc
    ips = {info[4][0] for info in infos}
    if not ips:
        raise TargetValidationError("No DNS records found")
    if any(not _is_public_ip(ip) for ip in ips):
        raise TargetValidationError("Resolved IP includes disallowed address space")
    return ips


def validate_target(target: str, config: AppConfig) -> ValidatedTarget:
    normalized = normalize_url(target)
    parsed = urlparse(normalized)
    if not parsed.hostname:
        raise TargetValidationError("Target URL missing hostname")
    hostname = parsed.hostname.lower()
    scope = ScopeEnforcer(config.scope)
    if not scope.is_host_authorized(hostname):
        raise TargetValidationError(f"Target host {hostname!r} is not in authorized scope")
    ips = resolve_public_ips(hostname)
    return ValidatedTarget(normalized_url=normalized, hostname=hostname, resolved_ips=ips)


def revalidate_dns(hostname: str, baseline_ips: set[str]) -> None:
    latest = resolve_public_ips(hostname)
    if latest != baseline_ips:
        raise TargetValidationError("DNS resolution changed during scan; possible rebinding risk")
