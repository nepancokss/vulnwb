import asyncio

import pytest

from sentinelscan.config import AppConfig
from sentinelscan.http_client import HTTPClientError, SafeHTTPClient


class DummyResponse:
    def __init__(self, content: bytes) -> None:
        self.content = content


def test_response_size_limit_enforced() -> None:
    client = SafeHTTPClient(AppConfig(), {"example.com": {"93.184.216.34"}})

    async def run() -> None:
        response = DummyResponse(b"a" * 15)
        with pytest.raises(HTTPClientError):
            await client._enforce_body_limit(response, 10)
        await client.aclose()

    asyncio.run(run())
