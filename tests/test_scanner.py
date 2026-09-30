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


def test_location_points_to_external_detects_every_bypass_variant():
    from redirectme.payloads import build_payloads

    config = make_config(external_url="https://evil.example.com")
    scanner = RedirectScanner("https://target.com", config)
    base_url = "https://target.com/page?next=X"

    for payload in build_payloads("next", "target.com", "https://evil.example.com"):
        assert scanner._location_points_to_external(base_url, payload), (
            f"payload not detected when reflected verbatim: {payload!r}"
        )


def test_location_points_to_external_has_no_false_positives():
    config = make_config(external_url="https://evil.example.com")
    scanner = RedirectScanner("https://target.com", config)
    base_url = "https://target.com/page?next=X"

    safe_locations = [
        "https://target.com/dashboard",
        "/relative/path",
        # adversarial: contains the external host as a substring, but the real
        # host is a different, unrelated domain the attacker doesn't control.
        "https://evil.example.com.attacker.test/phish",
        "https://notevil.example.com",
        # a real subdomain of the TARGET must never be treated as pointing
        # to the external host, even though our subdomain-confusion matching
        # accepts subdomains of the external host.
        "https://sub.target.com/ok",
        "https://evilXexample.com",
    ]
    for location in safe_locations:
        assert not scanner._location_points_to_external(base_url, location), (
            f"false positive on safe location: {location!r}"
        )


def test_crawl_detects_vulnerable_param(requests_mock):
    # requests_mock matches the most-recently-registered matcher first, so the
    # catch-all must be registered before the more specific matchers below.
    # The link path contains "redirect" so it qualifies as a Tier 2 entry
    # point (see ENTRY_POINT_HINTS) and gets the full guessed-parameter
    # battery instead of just its own (nonexistent) query parameters.
    requests_mock.get(ANY_URL, status_code=200, headers={"Content-Type": "text/html"})
    requests_mock.get(
        "http://example.com",
        text='<html><body><a href="/redirect">link</a></body></html>',
        headers={"Content-Type": "text/html"},
    )
    requests_mock.get(
        "http://example.com/redirect",
        text="<html></html>",
        headers={"Content-Type": "text/html"},
    )
    requests_mock.get(
        "http://example.com/redirect?url=https%3A%2F%2Fevil.example.com",
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
    # double-scheme, userinfo, percent-encoded, subdomain confusion, double
    # encoding, control-char, missing slashes) into Location was never
    # detected. Each variant `build_payloads` generates must be individually
    # detectable when the server reflects that exact string. The link path
    # contains "redirect" so it's a Tier 2 entry point (see ENTRY_POINT_HINTS).
    requests_mock.get(ANY_URL, status_code=200, headers={"Content-Type": "text/html"})
    requests_mock.get(
        "http://example.com",
        text='<html><body><a href="/redirect">link</a></body></html>',
        headers={"Content-Type": "text/html"},
    )
    requests_mock.get(
        "http://example.com/redirect",
        text="<html></html>",
        headers={"Content-Type": "text/html"},
    )
    vulnerable_url = f"http://example.com/redirect?{urlencode({'url': payload_value})}"
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


def test_strip_fragment_removes_fragment_but_keeps_query():
    from redirectme.scanner import _strip_fragment

    assert _strip_fragment("http://example.com/page#section") == "http://example.com/page"
    assert (
        _strip_fragment("http://example.com/page?x=1#section")
        == "http://example.com/page?x=1"
    )
    assert _strip_fragment("http://example.com/page") == "http://example.com/page"


def test_crawl_probes_the_starting_url_as_an_entry_point(requests_mock):
    # The starting URL is never discovered as an outbound "link" the way
    # every other crawled page is (nothing links to it), so it would never
    # get the Tier 2 guessed-parameter battery unless crawl() explicitly
    # probes it. Here the home page itself (not a link on it) is vulnerable.
    requests_mock.get(ANY_URL, status_code=200, headers={"Content-Type": "text/html"})
    requests_mock.get(
        "http://example.com", text="<html></html>", headers={"Content-Type": "text/html"}
    )
    requests_mock.get(
        "http://example.com?url=https%3A%2F%2Fevil.example.com",
        status_code=302,
        headers={"Location": "https://evil.example.com"},
    )

    config = make_config(max_pages=1)
    scanner = RedirectScanner("http://example.com", config)
    result = scanner.crawl()

    assert len(result.vulnerabilities) == 1
    assert result.vulnerabilities[0].type == "param"


def test_crawl_deduplicates_fragment_variants_and_fetches_page_once(requests_mock):
    # The catch-all must be registered first: requests_mock gives priority to
    # the most recently registered matcher, so the specific URLs below
    # (registered after) must take precedence over it.
    requests_mock.get(ANY_URL, status_code=200, headers={"Content-Type": "text/html"})
    requests_mock.get(
        "http://example.com",
        text='<html><body><a href="/page1#a">x</a><a href="/page1#b">y</a></body></html>',
        headers={"Content-Type": "text/html"},
    )
    requests_mock.get(
        "http://example.com/page1",
        text="<html></html>",
        headers={"Content-Type": "text/html"},
    )

    config = make_config(max_pages=10)
    scanner = RedirectScanner("http://example.com", config)
    result = scanner.crawl()

    # "/page1#a" and "/page1#b" are the same resource: only one extra page
    # counted beyond the home page, not two.
    assert result.pages_scanned == 2


def test_crawl_fetches_the_current_page_only_once_for_links_and_forms(requests_mock):
    # Before the fix, `scan_page_for_redirects` (link extraction) and
    # `scan_form_for_redirects` each fetched the current page separately.
    # The page under test is the crawl's starting URL with a form and no
    # outbound links: the Tier 2 self-probe on it (see
    # test_crawl_probes_the_starting_url_as_an_entry_point) only tests
    # parameters and deliberately skips the JS-redirect check precisely so it
    # doesn't add a fetch of its own here.
    requests_mock.get(ANY_URL, status_code=200, headers={"Content-Type": "text/html"})
    requests_mock.get(
        "http://example.com",
        text=(
            '<html><body><form action="/submit">'
            '<input name="next" value="/x"></form></body></html>'
        ),
        headers={"Content-Type": "text/html"},
    )

    config = make_config(max_pages=1)
    scanner = RedirectScanner("http://example.com", config)
    scanner.crawl()

    home_fetches = [
        req for req in requests_mock.request_history if req.url.rstrip("/") == "http://example.com"
    ]
    assert len(home_fetches) == 1


def test_scan_page_for_redirects_deduplicates_repeated_links(requests_mock):
    requests_mock.get(ANY_URL, status_code=200, headers={"Content-Type": "text/html"})
    requests_mock.get(
        "http://example.com",
        text=(
            '<html><body>'
            '<a href="/page1">x</a><a href="/page1">y</a><a href="/page1#a">z</a>'
            "</body></html>"
        ),
        headers={"Content-Type": "text/html"},
    )

    config = make_config(max_pages=1)
    scanner = RedirectScanner("http://example.com", config)
    links = scanner.scan_page_for_redirects("http://example.com")

    assert links.count("http://example.com/page1") == 1


def test_looks_like_entry_point():
    from redirectme.scanner import _looks_like_entry_point

    assert _looks_like_entry_point("http://example.com/login")
    assert _looks_like_entry_point("http://example.com/auth/sso?state=1")
    assert _looks_like_entry_point("http://example.com/account/logout")
    assert not _looks_like_entry_point("http://example.com/about-us")
    assert not _looks_like_entry_point("http://example.com/products/42")


def test_build_test_url_replaces_existing_param_instead_of_duplicating():
    from redirectme.scanner import _build_test_url

    url = _build_test_url("http://example.com/go?next=/home&lang=en", "next", "https://evil.example.com")
    assert url.count("next=") == 1
    assert "https%3A%2F%2Fevil.example.com" in url
    assert "lang=en" in url  # other existing params are preserved


def test_tier1_tests_a_links_own_existing_param_even_off_entry_points(requests_mock):
    # "/content" matches no ENTRY_POINT_HINTS keyword, so it must not get the
    # guessed-parameter battery — but it already carries `returnUrl` in its
    # own query string, which Tier 1 must still test regardless.
    requests_mock.get(ANY_URL, status_code=200, headers={"Content-Type": "text/html"})
    requests_mock.get(
        "http://example.com",
        text='<html><body><a href="/content?returnUrl=/ok">x</a></body></html>',
        headers={"Content-Type": "text/html"},
    )
    requests_mock.get(
        "http://example.com/content",
        text="<html></html>",
        headers={"Content-Type": "text/html"},
        complete_qs=False,
    )
    requests_mock.get(
        "http://example.com/content?returnUrl=https%3A%2F%2Fevil.example.com",
        status_code=302,
        headers={"Location": "https://evil.example.com"},
    )

    config = make_config(max_pages=2)
    scanner = RedirectScanner("http://example.com", config)
    result = scanner.crawl()

    assert len(result.vulnerabilities) == 1
    assert result.vulnerabilities[0].detail == "returnUrl=https://evil.example.com"


def test_tier2_skips_guessed_params_on_ordinary_non_entry_point_links(requests_mock):
    # "/content" has no query string of its own and matches no entry-point
    # keyword, so the guessed DEFAULT_REDIRECT_PARAMS battery (Tier 2) must
    # NOT run on it — even though it would be "vulnerable" to a guessed `url`
    # param, that's not how it's reachable and testing it here doesn't scale.
    requests_mock.get(ANY_URL, status_code=200, headers={"Content-Type": "text/html"})
    requests_mock.get(
        "http://example.com",
        text='<html><body><a href="/content">x</a></body></html>',
        headers={"Content-Type": "text/html"},
    )
    requests_mock.get(
        "http://example.com/content",
        text="<html></html>",
        headers={"Content-Type": "text/html"},
    )
    requests_mock.get(
        "http://example.com/content?url=https%3A%2F%2Fevil.example.com",
        status_code=302,
        headers={"Location": "https://evil.example.com"},
    )

    config = make_config(max_pages=2)
    scanner = RedirectScanner("http://example.com", config)
    result = scanner.crawl()

    assert len(result.vulnerabilities) == 0


def test_circuit_breaker_stops_after_consecutive_connection_failures(requests_mock):
    import requests

    from redirectme.scanner import MAX_CONSECUTIVE_FAILURES

    # A target actively resetting every connection (WAF/anti-bot/rate
    # limiting) must not be hammered for as long as max_pages allows —
    # crawl() should recognize it's blocked and stop.
    requests_mock.get(ANY_URL, exc=requests.exceptions.ConnectionError("connection reset"))

    events: list[str] = []
    config = make_config(max_pages=1000)
    scanner = RedirectScanner(
        "http://example.com", config, on_progress=lambda event, data: events.append(event)
    )
    result = scanner.crawl()

    assert scanner.aborted_reason is not None
    assert "blocking or rate-limiting" in scanner.aborted_reason
    assert events.count("scan_aborted") == 1
    error_count = events.count("request_error")
    # Stops at the threshold, not somewhere well beyond it (fast bail-out once
    # tripped) or before it (real transient failures shouldn't trip it early).
    assert error_count == MAX_CONSECUTIVE_FAILURES


def test_circuit_breaker_resets_after_a_successful_request(requests_mock):
    import requests

    from redirectme.scanner import MAX_CONSECUTIVE_FAILURES

    # Register a bounded number of failures, well under the threshold, then a
    # normal successful page — the counter must reset on success so isolated
    # flaky requests don't eventually trip the breaker by accumulating across
    # an otherwise-healthy scan.
    responses = [
        {"exc": requests.exceptions.ConnectionError("reset")}
        for _ in range(MAX_CONSECUTIVE_FAILURES - 1)
    ]
    responses.append(
        {"status_code": 200, "text": "<html></html>", "headers": {"Content-Type": "text/html"}}
    )
    requests_mock.get(ANY_URL, status_code=200, headers={"Content-Type": "text/html"})
    requests_mock.get("http://example.com/flaky", responses)

    config = make_config(max_pages=1)
    scanner = RedirectScanner("http://example.com", config)
    for _ in range(MAX_CONSECUTIVE_FAILURES - 1):
        assert scanner.request_with_retry("http://example.com/flaky", retries=1) is None
    assert scanner._consecutive_failures == MAX_CONSECUTIVE_FAILURES - 1
    assert not scanner._aborted.is_set()

    response = scanner.request_with_retry("http://example.com/flaky", retries=1)
    assert response is not None
    assert scanner._consecutive_failures == 0
    assert not scanner._aborted.is_set()
