# SentinelScan

SentinelScan is a modular Python CLI for **authorized defensive web security testing**.

## Responsible use policy
- Scan only assets you own or are explicitly authorized to test.
- `--confirm-authorized` is required.
- Scope is enforced through `authorized_hosts`.
- Out-of-scope redirects are blocked.
- Private, loopback, link-local, multicast, reserved, and metadata IPs are blocked by default.

## Features
- Safe URL normalization and scope enforcement
- DNS revalidation to reduce rebinding risk
- Bounded async HTTP requests with timeout/concurrency/rate/response-size limits
- Passive checks:
  - security headers
  - cookie attributes
  - TLS inspection
  - information disclosure indicators
  - robots/sitemap summaries
  - directory listing indicators
  - passive XSS and SQLi indicators
- HTML and JSON reporting

## Installation (Linux/Windows)
```bash
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell
# .venv\Scripts\Activate.ps1
pip install -e .
```

## Usage
```bash
sentinelscan validate-scope config.toml
sentinelscan scan https://app.example.com --confirm-authorized --config config.toml --output reports --format html,json
sentinelscan version
```

## Sample configuration
```toml
[scope]
authorized_hosts = ["example.com", "app.example.com"]
allow_subdomains = true

[limits]
timeout_seconds = 10.0
max_concurrency = 5
rate_limit_per_host = 2.0
max_redirects = 3
max_response_bytes = 1000000
max_scan_seconds = 300
max_pages = 10

[checks]
passive_only = true
info_paths = ["/robots.txt", "/sitemap.xml", "/.well-known/security.txt"]
directory_listing_paths = ["/", "/assets/", "/uploads/"]
```

## Testing and linting
```bash
pytest -q
ruff check .
ruff format --check .
```

## Known limitations
- Passive signals may include false positives.
- No brute-force, auth bypass, exploit execution, destructive testing, or data extraction.
- robots.txt entries are informational and not vulnerabilities on their own.
