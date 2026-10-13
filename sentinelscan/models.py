from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field, HttpUrl, field_validator


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex)
    title: str
    category: str
    severity: Severity
    confidence: Confidence
    target_url: HttpUrl
    description: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    remediation: str
    references: list[str] = Field(default_factory=list)
    check_name: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @field_validator("references")
    @classmethod
    def normalize_refs(cls, refs: list[str]) -> list[str]:
        return [ref.strip() for ref in refs if ref.strip()]


class ScanMetadata(BaseModel):
    target_url: HttpUrl
    started_at: datetime
    finished_at: datetime
    passive_only: bool
    scope_hosts: list[str]
    scanner_version: str
    limitations: list[str] = Field(default_factory=list)


class ScanResult(BaseModel):
    metadata: ScanMetadata
    findings: list[Finding]
