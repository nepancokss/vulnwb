import pytest

from sentinelscan.config import AppConfig
from sentinelscan.scope import ScopeEnforcer, ScopeError
from sentinelscan.target_validation import TargetValidationError, revalidate_dns, validate_target
from sentinelscan.utils.url_utils import normalize_url


def test_normalize_url_adds_scheme() -> None:
    assert normalize_url("example.com") == "https://example.com/"


def test_scope_enforcement_blocks_outside_host() -> None:
    config = AppConfig()
    config.scope.authorized_hosts = ["example.com"]
    enforcer = ScopeEnforcer(config.scope)
    with pytest.raises(ScopeError):
        enforcer.ensure_url_in_scope("https://evil.com/")


def test_validate_target_rejects_out_of_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    config = AppConfig()
    config.scope.authorized_hosts = ["example.com"]
    monkeypatch.setattr(
        "sentinelscan.target_validation.resolve_public_ips",
        lambda _: {"93.184.216.34"},
    )
    with pytest.raises(TargetValidationError):
        validate_target("https://unauthorized.test", config)


def test_dns_rebinding_detection(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "sentinelscan.target_validation.resolve_public_ips",
        lambda _: {"93.184.216.35"},
    )
    with pytest.raises(TargetValidationError):
        revalidate_dns("example.com", {"93.184.216.34"})
