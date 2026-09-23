from urllib.parse import urlencode

import pytest
from requests_mock import ANY as ANY_URL

from redirectme.config import AppConfig
from redirectme.payloads import build_payloads
from redirectme.scanner import RedirectScanner, same_site


def make_config(**overrides):
    base = dict(
        external_url="https://evil.example.com",
        max_pages=10,
        timeout=5,
        min_delay=0,
        max_delay=0,
        max_workers=1,
        use_bypass_payloads=False,
        respect_robots=False,
        report_format="txt",
        report_output_dir="reports",
    )
    base.update(overrides)
    return AppConfig(**base)


def test_same_site_compares_exact_netloc():
    assert same_site("https://example.com/path", "example.com")
    assert not same_site("https://evil.example.com.attacker.test/path", "example.com")


def test_crawl_detects_vulnerable_param(requests_mock):
    # requests_mock matches the most-recently-registered matcher first, so the
    # catch-all must be registered before the more specific matchers below.
    requests_mock.get(ANY_URL, status_code=200, headers={"Content-Type": "text/html"})
    requests_mock.get(
        "http://example.com",
        text='<html><body><a href="/page1">link</a></body></html>',
        headers={"Content-Type": "text/html"},
    )
    requests_mock.get(
        "http://example.com/page1",
        text="<html></html>",
        headers={"Content-Type": "text/html"},
    )
    requests_mock.get(
        "http://example.com/page1?url=https%3A%2F%2Fevil.example.com",
        status_code=302,
        headers={"Location": "https://evil.example.com"},
    )

    config = make_config(max_workers=2)
    scanner = RedirectScanner("http://example.com", config)
    result = scanner.crawl()

    assert result.pages_scanned == 2
    assert len(result.vulnerabilities) == 1
    assert result.vulnerabilities[0].type == "param"
    assert "url=" in result.vulnerabilities[0].url


BYPASS_PAYLOADS = build_payloads(
    "url", "example.com", "https://evil.example.com", use_bypass=True
)


@pytest.mark.parametrize("payload_value", BYPASS_PAYLOADS)
def test_crawl_detects_each_bypass_payload_variant(requests_mock, payload_value):
    # Regression test for Finding 1: `is_open_redirect` used to substring-match
    # the full `external_url` against the Location header, so a server that
    # naively reflects a *bypass* payload (protocol-relative, backslash,
    # double-scheme, userinfo, percent-encoded) into Location was never
    # detected. Each of the 6 variants `build_payloads` generates must be
    # individually detectable when the server reflects that exact string.
    requests_mock.get(ANY_URL, status_code=200, headers={"Content-Type": "text/html"})
    requests_mock.get(
        "http://example.com",
        text='<html><body><a href="/page1">link</a></body></html>',
        headers={"Content-Type": "text/html"},
    )
    requests_mock.get(
        "http://example.com/page1",
        text="<html></html>",
        headers={"Content-Type": "text/html"},
    )
    vulnerable_url = f"http://example.com/page1?{urlencode({'url': payload_value})}"
    requests_mock.get(
        vulnerable_url,
        status_code=302,
        headers={"Location": payload_value},
    )

    config = make_config(max_workers=2, use_bypass_payloads=True)
    scanner = RedirectScanner("http://example.com", config)
    result = scanner.crawl()

    assert len(result.vulnerabilities) == 1
    assert result.vulnerabilities[0].type == "param"
    assert result.vulnerabilities[0].detail == f"url={payload_value}"


def test_crawl_detects_vulnerable_get_form(requests_mock):
    # Regression test for Finding 2: `scan_form_for_redirects` built a poisoned
    # `data` dict but never sent it (request_with_retry took no params/data), so
    # form scanning was a complete no-op. A GET form whose redirect param leads
    # to the external host must now be reported as a "form" vulnerability.
    requests_mock.get(ANY_URL, status_code=200, headers={"Content-Type": "text/html"})
    requests_mock.get(
        "http://example.com",
        text=(
            '<html><body>'
            '<form method="get" action="/login">'
            '<input name="next" value="/home">'
            "</form>"
            "</body></html>"
        ),
        headers={"Content-Type": "text/html"},
    )
    requests_mock.get(
        "http://example.com/login?next=https%3A%2F%2Fevil.example.com",
        status_code=302,
        headers={"Location": "https://evil.example.com"},
    )

    config = make_config(use_bypass_payloads=False)
    scanner = RedirectScanner("http://example.com", config)
    result = scanner.crawl()

    form_vulns = [v for v in result.vulnerabilities if v.type == "form"]
    assert len(form_vulns) == 1
    assert form_vulns[0].url == "http://example.com/login"


def test_crawl_does_not_flag_safe_form(requests_mock):
    # Companion test for Finding 2: a form whose submission does NOT redirect
    # externally must not be reported as vulnerable (no false positive now that
    # the poisoned data is actually sent).
    requests_mock.get(ANY_URL, status_code=200, headers={"Content-Type": "text/html"})
    requests_mock.get(
        "http://example.com",
        text=(
            '<html><body>'
            '<form method="get" action="/login">'
            '<input name="next" value="/home">'
            "</form>"
            "</body></html>"
        ),
        headers={"Content-Type": "text/html"},
    )
    requests_mock.get(
        "http://example.com/login?next=https%3A%2F%2Fevil.example.com",
        status_code=200,
        text="<html></html>",
        headers={"Content-Type": "text/html"},
    )

    config = make_config(use_bypass_payloads=False)
    scanner = RedirectScanner("http://example.com", config)
    result = scanner.crawl()

    assert not [v for v in result.vulnerabilities if v.type == "form"]


def test_crawl_detects_vulnerable_post_form(requests_mock):
    # POST forms must send the poisoned data as a form-encoded body, not query
    # params, and still be checked against the same external-host logic.
    requests_mock.get(ANY_URL, status_code=200, headers={"Content-Type": "text/html"})
    requests_mock.get(
        "http://example.com",
        text=(
            '<html><body>'
            '<form method="post" action="/login">'
            '<input name="next" value="/home">'
            "</form>"
            "</body></html>"
        ),
        headers={"Content-Type": "text/html"},
    )
    requests_mock.post(
        "http://example.com/login",
        status_code=302,
        headers={"Location": "https://evil.example.com"},
    )

    config = make_config(use_bypass_payloads=False)
    scanner = RedirectScanner("http://example.com", config)
    result = scanner.crawl()

    form_vulns = [v for v in result.vulnerabilities if v.type == "form"]
    assert len(form_vulns) == 1
    posted_bodies = [
        req.text for req in requests_mock.request_history if req.method == "POST"
    ]
    assert any("next=" in (body or "") for body in posted_bodies)


def test_request_with_retry_throttles_each_attempt(requests_mock, monkeypatch):
    # Regression test for Finding 3: each HTTP attempt made by
    # `request_with_retry` (not just once per page) must sleep a random amount
    # within [min_delay, max_delay] before firing the request.
    sleep_calls = []
    monkeypatch.setattr(
        "redirectme.scanner.time.sleep", lambda seconds: sleep_calls.append(seconds)
    )
    url = "http://example.com/throttled"
    requests_mock.get(url, status_code=200, text="ok", headers={"Content-Type": "text/html"})

    config = make_config(min_delay=1.5, max_delay=3.0)
    scanner = RedirectScanner("http://example.com", config)
    response = scanner.request_with_retry(url)

    assert response.status_code == 200
    assert len(sleep_calls) == 1
    assert 1.5 <= sleep_calls[0] <= 3.0


def test_request_with_retry_handles_429(requests_mock, monkeypatch):
    monkeypatch.setattr("redirectme.scanner.time.sleep", lambda seconds: None)
    url = "http://example.com/limited"
    requests_mock.get(
        url,
        [
            {"status_code": 429, "headers": {"Retry-After": "1"}},
            {"status_code": 200, "text": "ok", "headers": {"Content-Type": "text/html"}},
        ],
    )
    config = make_config()
    scanner = RedirectScanner("http://example.com", config)
    response = scanner.request_with_retry(url)
    assert response.status_code == 200


def test_respects_robots_txt(requests_mock, monkeypatch):
    monkeypatch.setattr("redirectme.scanner.time.sleep", lambda seconds: None)
    # requests_mock matches the most-recently-registered matcher first, so the
    # catch-all must be registered before the more specific matchers below.
    requests_mock.get(ANY_URL, status_code=200, headers={"Content-Type": "text/html"})
    requests_mock.get(
        "http://example.com/robots.txt",
        text="User-agent: *\nDisallow: /private\n",
        headers={"Content-Type": "text/plain"},
    )
    requests_mock.get(
        "http://example.com",
        text='<html><body><a href="/private">x</a><a href="/public">y</a></body></html>',
        headers={"Content-Type": "text/html"},
    )
    requests_mock.get(
        "http://example.com/public",
        text="<html></html>",
        headers={"Content-Type": "text/html"},
    )

    config = make_config(respect_robots=True, max_pages=10)
    scanner = RedirectScanner("http://example.com", config)
    scanner.crawl()

    requested_urls = {req.url for req in requests_mock.request_history}
    assert not any(url.startswith("http://example.com/private") for url in requested_urls)
    assert "http://example.com/public" in requested_urls
