from __future__ import annotations

from abc import ABC, abstractmethod

from sentinelscan.models import Finding


class Check(ABC):
    name: str

    @abstractmethod
    async def run(self, target_url: str) -> list[Finding]:
        raise NotImplementedError
