from requests_mock import ANY as ANY_URL

from redirectme.config import AppConfig
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
