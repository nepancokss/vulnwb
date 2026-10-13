from __future__ import annotations

import asyncio
import time
from collections import defaultdict


class AsyncRateLimiter:
    def __init__(self, requests_per_second: float) -> None:
        self._min_interval = 1.0 / requests_per_second
        self._last_seen: dict[str, float] = defaultdict(float)
        self._lock = asyncio.Lock()

    async def wait(self, key: str) -> None:
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_seen[key]
            sleep_for = self._min_interval - elapsed
            if sleep_for > 0:
                await asyncio.sleep(sleep_for)
            self._last_seen[key] = time.monotonic()
