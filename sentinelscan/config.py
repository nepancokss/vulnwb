from __future__ import annotations

import tomllib
from pathlib import Path

from pydantic import BaseModel, Field, PositiveInt, field_validator


class ScannerLimits(BaseModel):
    timeout_seconds: float = Field(default=10.0, ge=1.0, le=120.0)
    max_concurrency: PositiveInt = 5
    rate_limit_per_host: float = Field(default=2.0, ge=0.1, le=20.0)
    max_redirects: int = Field(default=3, ge=0, le=10)
    max_response_bytes: int = Field(default=1_000_000, ge=1024, le=5_000_000)
    max_scan_seconds: int = Field(default=300, ge=10, le=3600)
    max_pages: int = Field(default=10, ge=1, le=200)


class ScopeConfig(BaseModel):
    authorized_hosts: list[str] = Field(default_factory=list)
    allow_subdomains: bool = True

    @field_validator("authorized_hosts")
    @classmethod
    def lower_hosts(cls, hosts: list[str]) -> list[str]:
        return sorted({host.strip().lower() for host in hosts if host.strip()})


class CheckConfig(BaseModel):
    passive_only: bool = True
    info_paths: list[str] = Field(
        default_factory=lambda: [
            "/robots.txt",
            "/sitemap.xml",
            "/.well-known/security.txt",
        ]
    )
    directory_listing_paths: list[str] = Field(
        default_factory=lambda: ["/", "/assets/", "/uploads/"]
    )


class AppConfig(BaseModel):
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    limits: ScannerLimits = Field(default_factory=ScannerLimits)
    checks: CheckConfig = Field(default_factory=CheckConfig)


def load_config(path: Path) -> AppConfig:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    return AppConfig.model_validate(data)
