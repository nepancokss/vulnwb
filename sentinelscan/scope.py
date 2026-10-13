from __future__ import annotations

from urllib.parse import urlparse

from sentinelscan.config import ScopeConfig
from sentinelscan.utils.url_utils import strip_default_port


class ScopeError(ValueError):
    pass


class ScopeEnforcer:
    def __init__(self, config: ScopeConfig) -> None:
        self._config = config

    def is_host_authorized(self, hostname: str) -> bool:
        host = hostname.lower()
        allowed = self._config.authorized_hosts
        if not allowed:
            return False
        if host in allowed:
            return True
        if self._config.allow_subdomains:
            return any(host.endswith(f".{base}") for base in allowed)
        return False

    def ensure_url_in_scope(self, url: str) -> None:
        parsed = urlparse(url)
        if not parsed.hostname:
            raise ScopeError("URL has no hostname")
        host = strip_default_port(parsed.netloc.lower()).split(":", 1)[0]
        if not self.is_host_authorized(host):
            raise ScopeError(f"Host {host!r} is outside authorized scope")
