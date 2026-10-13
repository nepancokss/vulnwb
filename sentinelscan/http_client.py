from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from sentinelscan.config import AppConfig
from sentinelscan.scope import ScopeEnforcer, ScopeError
from sentinelscan.target_validation import revalidate_dns
from sentinelscan.utils.rate_limiter import AsyncRateLimiter


class HTTPClientError(RuntimeError):
    pass


class SafeHTTPClient:
    def __init__(self, config: AppConfig, baseline_dns: dict[str, set[str]]) -> None:
        limits = config.limits
        self._config = config
        self._scope = ScopeEnforcer(config.scope)
        self._baseline_dns = baseline_dns
        self._semaphore = asyncio.Semaphore(limits.max_concurrency)
        self._limiter = AsyncRateLimiter(limits.rate_limit_per_host)
        self._timeout = httpx.Timeout(
            connect=limits.timeout_seconds,
            read=limits.timeout_seconds,
            write=limits.timeout_seconds,
            pool=limits.timeout_seconds,
        )
        self._client = httpx.AsyncClient(timeout=self._timeout, follow_redirects=False, verify=True)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def get(self, url: str, *, max_bytes: int | None = None) -> httpx.Response:
        response_limit = max_bytes or self._config.limits.max_response_bytes
        current_url = url
        redirects = 0
        while True:
            parsed = urlparse(current_url)
            host = parsed.hostname
            if not host:
                raise HTTPClientError("URL missing hostname")
            if host in self._baseline_dns:
                revalidate_dns(host, self._baseline_dns[host])
            await self._limiter.wait(host)
            async with self._semaphore:
                try:
                    response = await self._client.get(current_url)
                except httpx.HTTPError as exc:
                    raise HTTPClientError(str(exc)) from exc

            await self._enforce_body_limit(response, response_limit)
            if response.is_redirect:
                location = response.headers.get("location")
                if not location:
                    return response
                redirects += 1
                if redirects > self._config.limits.max_redirects:
                    raise HTTPClientError("Maximum redirects exceeded")
                next_url = urljoin(str(response.request.url), location)
                try:
                    self._scope.ensure_url_in_scope(next_url)
                except ScopeError as exc:
                    raise HTTPClientError("Redirected outside authorized scope") from exc
                current_url = next_url
                continue
            return response

    async def _enforce_body_limit(self, response: httpx.Response, max_bytes: int) -> None:
        body = response.content
        if len(body) > max_bytes:
            raise HTTPClientError("Response exceeded configured maximum size")


@asynccontextmanager
async def build_http_client(config: AppConfig, baseline_dns: dict[str, set[str]]) -> Any:
    client = SafeHTTPClient(config, baseline_dns)
    try:
        yield client
    finally:
        await client.aclose()
