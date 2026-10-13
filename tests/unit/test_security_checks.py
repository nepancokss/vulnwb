from sentinelscan.checks.cookies import analyze_cookie_headers
from sentinelscan.checks.passive_sqli import analyze_passive_sqli
from sentinelscan.checks.passive_xss import analyze_passive_xss
from sentinelscan.checks.security_headers import analyze_security_headers


def test_security_headers_missing_detected() -> None:
    findings = analyze_security_headers("https://example.com/", {"Server": "test"})
    titles = {f.title for f in findings}
    assert "Missing Content-Security-Policy" in titles


def test_cookie_values_not_exposed() -> None:
    findings = analyze_cookie_headers("https://example.com", ["sessionid=secretvalue; Path=/"])
    assert findings
    for finding in findings:
        assert "secretvalue" not in str(finding.evidence)


def test_passive_xss_indicator_low_confidence() -> None:
    findings = analyze_passive_xss(
        "https://example.com/?q=<script>",
        "<html><body><script></body></html>",
        "text/html",
    )
    assert findings
    assert findings[0].confidence.value == "low"


def test_passive_sqli_indicator_detected() -> None:
    body = "You have an error in your SQL syntax near 'x'"
    findings = analyze_passive_sqli("https://example.com", body)
    assert findings
