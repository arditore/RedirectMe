"""RedirectMe scan engine: crawling, open redirect detection."""
from __future__ import annotations

import logging
import random
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Callable, Optional
from urllib.parse import unquote, urljoin, urlencode, urlparse, urlsplit, urlunsplit
from urllib.robotparser import RobotFileParser

import requests
from bs4 import BeautifulSoup

from redirectme.config import AppConfig
from redirectme.payloads import DEFAULT_REDIRECT_PARAMS, build_payloads
from redirectme.report import ScanResult, Vulnerability

DEFAULT_MAX_RETRIES = 5

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Firefox/89.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Edge/91.0.864.59",
]

JS_REDIRECT_REGEX = re.compile(
    r"(?:window\.location\.href|location\.replace)\s*\(\s*['\"]([^'\"]+)['\"]"
)

# Detects a "duplicate scheme" like "https:https://evil.example.com" (a bypass
# of naive validation that prefixes "https:" without checking whether the
# value already has one) so it can be neutralized before resolution.
_DUPLICATE_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:(?=[a-zA-Z][a-zA-Z0-9+.-]*://)")

logger = logging.getLogger("redirectme")

ProgressCallback = Callable[[str, dict], None]


def same_site(url: str, target_netloc: str) -> bool:
    """Checks that `url` belongs exactly to the target domain (netloc comparison)."""
    return urlparse(url).netloc == target_netloc


def _extract_hrefs(soup: BeautifulSoup) -> list[str]:
    """Raw (unresolved) links from an already-parsed page."""
    return [a["href"] for a in soup.find_all("a", href=True)]


def _strip_fragment(url: str) -> str:
    """Removes the fragment (#...) from a URL: it is never sent to the server, so
    `/page` and `/page#section` are the same resource and must not count as two
    distinct pages for `max_pages`/`visited_urls` purposes."""
    scheme, netloc, path, query, _fragment = urlsplit(url)
    return urlunsplit((scheme, netloc, path, query, ""))


class RedirectScanner:
    """Crawls a site and detects open redirects."""

    def __init__(
        self, target: str, config: AppConfig, on_progress: Optional[ProgressCallback] = None
    ):
        self.target = target.rstrip("/")
        self.config = config
        self.target_netloc = urlparse(self.target).netloc
        self.on_progress = on_progress or (lambda event, data: None)
        self.visited_urls: set[str] = set()
        self.visited_lock = threading.Lock()
        self.vulnerabilities: list[Vulnerability] = []
        self.vuln_lock = threading.Lock()
        self.session = requests.Session()
        self._start_time: datetime | None = None
        self._start_perf: float | None = None
        self._robot_parser: RobotFileParser | None = None
        if self.config.respect_robots:
            self._robot_parser = self._load_robots_txt()

    def _load_robots_txt(self) -> RobotFileParser:
        parser = RobotFileParser()
        robots_url = urljoin(self.target + "/", "/robots.txt")
        parser.set_url(robots_url)
        try:
            response = self.session.get(robots_url, timeout=self.config.timeout)
            parser.parse(response.text.splitlines() if response.status_code == 200 else [])
        except requests.exceptions.RequestException:
            parser.parse([])
        return parser

    def _is_allowed(self, url: str) -> bool:
        if self._robot_parser is None:
            return True
        return self._robot_parser.can_fetch("*", url)

    def request_with_retry(
        self,
        url: str,
        retries: int | None = None,
        method: str = "get",
        params: dict | None = None,
        data: dict | None = None,
    ) -> requests.Response | None:
        """Performs an HTTP request (GET by default) with per-request throttling,
        429 handling and exponential backoff."""
        retries = DEFAULT_MAX_RETRIES if retries is None else retries
        backoff_factor = 2
        for attempt in range(retries):
            time.sleep(random.uniform(self.config.min_delay, self.config.max_delay))
            try:
                response = self.session.request(
                    method,
                    url,
                    params=params,
                    data=data,
                    timeout=self.config.timeout,
                    headers={"User-Agent": random.choice(USER_AGENTS)},
                    allow_redirects=False,
                )
            except requests.exceptions.RequestException as exc:
                logger.error("Request error on %s: %s", url, exc)
                return None

            if response.status_code == 429:
                retry_after = response.headers.get("Retry-After")
                wait_time = int(retry_after) if retry_after else backoff_factor * (2**attempt)
                logger.warning(
                    "429 received on %s, waiting %ss before retrying...", url, wait_time
                )
                time.sleep(wait_time)
                continue
            return response
        return None

    def _fetch_and_parse(self, url: str) -> BeautifulSoup | None:
        """Fetches an HTML page and parses it only once. Shared by link extraction
        and form scanning to avoid re-fetching the same page twice."""
        response = self.request_with_retry(url)
        if response is None or "text/html" not in response.headers.get("Content-Type", ""):
            return None
        return BeautifulSoup(response.text, "html.parser")

    def get_all_links(self, url: str) -> list[str]:
        """Fetches all links (href) present on a page."""
        soup = self._fetch_and_parse(url)
        if soup is None:
            return []
        return _extract_hrefs(soup)

    def get_js_redirects(self, url: str) -> list[str]:
        """Looks for JavaScript-triggered redirects on a page."""
        response = self.request_with_retry(url)
        if response is None:
            return []
        return JS_REDIRECT_REGEX.findall(response.text)

    def is_open_redirect(self, test_url: str) -> bool:
        """Checks whether `test_url` redirects (3xx) to the external test host."""
        response = self.request_with_retry(test_url, retries=3)
        if response is None or not (300 <= response.status_code < 400):
            return False
        return self._response_points_to_external(response, test_url)

    def _response_points_to_external(self, response: requests.Response, base_url: str) -> bool:
        """Checks whether `response`'s Location header points to the configured external host."""
        location = response.headers.get("Location", "")
        return self._location_points_to_external(base_url, location)

    def _location_points_to_external(self, base_url: str, location: str) -> bool:
        """Resolves `location` (relative or absolute) against `base_url` and compares
        its host to the configured external host, neutralizing the common bypasses
        generated by `build_payloads` (protocol-relative URL, backslash, duplicate
        scheme, %2F encoding, userinfo authority confusion)."""
        if not location:
            return False
        external_host = urlsplit(self.config.external_url).hostname
        if not external_host:
            return False

        # Neutralize %2F encoding and the backslash->slash normalization that
        # browsers apply (not RFC-compliant, but real browser behavior for
        # "special" schemes).
        candidate = unquote(location).replace("\\", "/")
        candidate = _DUPLICATE_SCHEME_RE.sub("", candidate)

        def _matches(value: str) -> bool:
            resolved = urlsplit(urljoin(base_url, value))
            return resolved.hostname == external_host

        if _matches(candidate):
            return True

        # "target_host@external_host" reflected as-is, with no scheme or "//": a
        # vulnerable server may insert it directly into an authority context
        # (e.g. a Location built as "https://" + value).
        if "@" in candidate and "://" not in candidate and not candidate.startswith("/"):
            return _matches("//" + candidate)

        return False

    def _test_link(self, full_link: str) -> None:
        if not self._is_allowed(full_link):
            return
        for param in DEFAULT_REDIRECT_PARAMS:
            for value in build_payloads(
                param, self.target_netloc, self.config.external_url, self.config.use_bypass_payloads
            ):
                separator = "&" if "?" in full_link else "?"
                test_url = f"{full_link}{separator}{urlencode({param: value})}"
                self.on_progress("link_tested", {"url": test_url})
                if self.is_open_redirect(test_url):
                    self._report_vulnerability("param", test_url, f"{param}={value}")

        for js_url in self.get_js_redirects(full_link):
            absolute_js_url = urljoin(full_link, js_url)
            if same_site(absolute_js_url, self.target_netloc) and self.is_open_redirect(
                absolute_js_url
            ):
                self._report_vulnerability(
                    "javascript", absolute_js_url, f"from {full_link}"
                )

    def scan_page_for_redirects(
        self, page_url: str, soup: BeautifulSoup | None = None
    ) -> list[str]:
        """Tests a page's links (in parallel) and returns all absolute links found.

        If `soup` is provided (page already fetched by the caller), avoids a new request.
        """
        if soup is None:
            soup = self._fetch_and_parse(page_url)
        if soup is None:
            return []
        # dict.fromkeys: deduplicates while preserving order (several
        # anchors/fragments pointing to the same URL must not be tested twice).
        links = list(
            dict.fromkeys(
                _strip_fragment(urljoin(page_url, href)) for href in _extract_hrefs(soup)
            )
        )
        same_site_links = [link for link in links if same_site(link, self.target_netloc)]
        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            list(executor.map(self._test_link, same_site_links))
        return links

    def scan_form_for_redirects(self, page_url: str, soup: BeautifulSoup | None = None) -> None:
        """Submits a page's forms, injecting the external URL into redirect fields.
        If `soup` is provided (page already fetched by the caller), avoids a new
        request."""
        if not self._is_allowed(page_url):
            return
        if soup is None:
            soup = self._fetch_and_parse(page_url)
        if soup is None:
            return

        for form in soup.find_all("form"):
            action = form.get("action")
            if not action:
                continue
            full_action = urljoin(page_url, action)
            if not same_site(full_action, self.target_netloc):
                continue

            form_data = {
                tag.get("name"): tag.get("value", "")
                for tag in form.find_all("input")
                if tag.get("name")
            }
            touched = False
            for param in DEFAULT_REDIRECT_PARAMS:
                if param in form_data:
                    form_data[param] = self.config.external_url
                    touched = True
            if not touched:
                continue

            method = (form.get("method") or "get").strip().lower()
            if method not in ("get", "post"):
                method = "get"

            form_response = self.request_with_retry(
                full_action,
                retries=3,
                method=method,
                params=form_data if method == "get" else None,
                data=form_data if method == "post" else None,
            )
            if form_response is None or not (300 <= form_response.status_code < 400):
                continue
            if self._response_points_to_external(form_response, full_action):
                self._report_vulnerability("form", full_action, "form submission")

    def _report_vulnerability(self, vuln_type: str, url: str, detail: str) -> None:
        with self.vuln_lock:
            vuln = Vulnerability(type=vuln_type, url=url, detail=detail)
            self.vulnerabilities.append(vuln)
        logger.warning("[VULNERABLE] %s (%s)", url, detail)
        self.on_progress("vulnerability_found", {"vulnerability": vuln})

    def crawl(self) -> ScanResult:
        """Crawls the site breadth-first, up to `max_pages`, scanning every visited page."""
        self._start_time = datetime.now()
        self._start_perf = time.perf_counter()
        urls_to_visit = [self.target]

        while urls_to_visit and len(self.visited_urls) < self.config.max_pages:
            current_url = _strip_fragment(urls_to_visit.pop(0))
            with self.visited_lock:
                if current_url in self.visited_urls:
                    continue
                self.visited_urls.add(current_url)

            if not self._is_allowed(current_url):
                logger.info("Skipped (robots.txt): %s", current_url)
                continue

            self.on_progress(
                "page_scanned", {"url": current_url, "count": len(self.visited_urls)}
            )

            # A single request for the page: the HTML is reused for link
            # extraction and form scanning instead of being fetched twice.
            page_soup = self._fetch_and_parse(current_url)
            links = self.scan_page_for_redirects(current_url, page_soup)
            self.scan_form_for_redirects(current_url, page_soup)

            for link in links:
                if same_site(link, self.target_netloc) and link not in self.visited_urls:
                    urls_to_visit.append(link)

        return self.result()

    def result(self) -> ScanResult:
        """Builds a `ScanResult` from the current state (scan finished or interrupted)."""
        duration = (
            time.perf_counter() - self._start_perf if self._start_perf is not None else 0.0
        )
        return ScanResult(
            target=self.target,
            started_at=self._start_time or datetime.now(),
            duration_s=duration,
            pages_scanned=len(self.visited_urls),
            vulnerabilities=list(self.vulnerabilities),
        )
