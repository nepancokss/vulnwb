from __future__ import annotations

from urllib.parse import urlparse, urlunparse


def normalize_url(url: str) -> str:
    candidate = url.strip()
    if not candidate:
        raise ValueError("Target URL cannot be empty")
    if "://" not in candidate:
        candidate = f"https://{candidate}"
    parsed = urlparse(candidate)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only http and https schemes are supported")
    if not parsed.hostname:
        raise ValueError("Target URL must include a hostname")
    clean_path = parsed.path or "/"
    return urlunparse(
        (parsed.scheme.lower(), parsed.netloc.lower(), clean_path, "", parsed.query, "")
    )


def strip_default_port(host: str) -> str:
    if host.endswith(":80"):
        return host[:-3]
    if host.endswith(":443"):
        return host[:-4]
    return host
