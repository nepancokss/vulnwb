import asyncio
import time

from sentinelscan.utils.rate_limiter import AsyncRateLimiter


def test_rate_limiter_waits() -> None:
    limiter = AsyncRateLimiter(10.0)

    async def run() -> float:
        start = time.monotonic()
        await limiter.wait("example.com")
        await limiter.wait("example.com")
        return time.monotonic() - start

    elapsed = asyncio.run(run())
    assert elapsed >= 0.09
