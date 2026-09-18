#!/usr/bin/env python3
"""RedirectMe - scanner de redirections ouvertes (open redirect).

Outil de sécurité offensive à usage autorisé uniquement : explore un site
web et teste ses liens, scripts JavaScript et formulaires à la recherche
de redirections ouvertes exploitables en phishing.
"""

from __future__ import annotations

import argparse
import logging
import random
import re
import sys
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlencode, urlparse

import requests
from bs4 import BeautifulSoup

DEFAULT_REDIRECT_PARAMS = [
    "url", "redirect", "next", "return", "to", "continue", "redirect_uri",
    "target", "destination", "goto", "next_url", "post_login_redirect",
    "continue_url", "after_login", "forward_to", "landing", "next_page",
    "path", "jump", "ref", "redir", "callback", "referred_by", "from", "link",
]

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

logger = logging.getLogger("redirectme")


@dataclass
class ScanConfig:
    target_domain: str
    external_url: str = "https://evil.example.com"
    max_pages: int = 100
    timeout: int = 5
    max_retries: int = 5
    delay_range: tuple[float, float] = (2.0, 5.0)
    redirect_params: list[str] = field(default_factory=lambda: list(DEFAULT_REDIRECT_PARAMS))
    output_file: str | None = None


def same_site(url: str, target_netloc: str) -> bool:
    """Vérifie que `url` appartient bien au domaine ciblé (comparaison exacte du netloc)."""
    return urlparse(url).netloc == target_netloc


class RedirectScanner:
    """Explore un site et détecte les redirections ouvertes."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.target_netloc = urlparse(config.target_domain).netloc
        self.visited_urls: set[str] = set()
        self.vulnerabilities: list[str] = []
        self.session = requests.Session()

    def request_with_retry(self, url: str, retries: int | None = None) -> requests.Response | None:
        """Effectue une requête GET avec gestion des erreurs 429 et backoff exponentiel."""
        retries = self.config.max_retries if retries is None else retries
        backoff_factor = 2
        for attempt in range(retries):
            try:
                response = self.session.get(
                    url,
                    timeout=self.config.timeout,
                    headers={"User-Agent": random.choice(USER_AGENTS)},
                    allow_redirects=False,
                )
            except requests.exceptions.RequestException as exc:
                logger.error("Erreur de requête sur %s : %s", url, exc)
                return None

            if response.status_code == 429:
                retry_after = response.headers.get("Retry-After")
                wait_time = int(retry_after) if retry_after else backoff_factor * (2 ** attempt)
                logger.warning("429 reçu sur %s, attente de %ss avant nouvel essai...", url, wait_time)
                time.sleep(wait_time)
                continue
            return response
        return None

    def get_all_links(self, url: str) -> list[str]:
        """Récupère tous les liens (href) présents sur une page."""
        response = self.request_with_retry(url)
        if response is None or "text/html" not in response.headers.get("Content-Type", ""):
            return []
        soup = BeautifulSoup(response.text, "html.parser")
        return [a["href"] for a in soup.find_all("a", href=True)]

    def get_js_redirects(self, url: str) -> list[str]:
        """Recherche les redirections déclenchées en JavaScript sur une page."""
        response = self.request_with_retry(url)
        if response is None:
            return []
        return JS_REDIRECT_REGEX.findall(response.text)

    def is_open_redirect(self, test_url: str) -> bool:
        """Vérifie si `test_url` redirige (3xx) vers l'URL externe de test."""
        response = self.request_with_retry(test_url, retries=3)
        if response is None or not (300 <= response.status_code < 400):
            return False
        location = response.headers.get("Location", "")
        return self.config.external_url in location

    def scan_page_for_redirects(self, page_url: str) -> None:
        """Teste les liens d'une page avec chaque paramètre de redirection connu."""
        for link in self.get_all_links(page_url):
            full_link = urljoin(page_url, link)
            if not same_site(full_link, self.target_netloc):
                continue

            for param in self.config.redirect_params:
                separator = "&" if "?" in full_link else "?"
                test_url = f"{full_link}{separator}{urlencode({param: self.config.external_url})}"
                if self.is_open_redirect(test_url):
                    self._report_vulnerability(f"{test_url} redirige vers {self.config.external_url}")

            for js_url in self.get_js_redirects(full_link):
                absolute_js_url = urljoin(full_link, js_url)
                if same_site(absolute_js_url, self.target_netloc) and self.is_open_redirect(absolute_js_url):
                    self._report_vulnerability(
                        f"Redirection JavaScript vers {self.config.external_url} depuis {full_link}"
                    )

    def scan_form_for_redirects(self, page_url: str) -> None:
        """Soumet les formulaires d'une page en injectant l'URL externe dans les champs de redirection."""
        response = self.request_with_retry(page_url)
        if response is None:
            return
        soup = BeautifulSoup(response.text, "html.parser")

        for form in soup.find_all("form"):
            action = form.get("action")
            if not action:
                continue
            full_action = urljoin(page_url, action)
            if not same_site(full_action, self.target_netloc):
                continue

            data = {
                tag.get("name"): tag.get("value", "")
                for tag in form.find_all("input")
                if tag.get("name")
            }
            for param in self.config.redirect_params:
                if param in data:
                    data[param] = self.config.external_url

            response = self.request_with_retry(full_action, retries=3)
            if response is not None and self.is_open_redirect(response.url):
                self._report_vulnerability(f"Formulaire {full_action} redirige vers {self.config.external_url}")
            else:
                logger.info("Formulaire sûr : %s", full_action)

    def _report_vulnerability(self, message: str) -> None:
        logger.warning("[VULNÉRABLE] %s", message)
        self.vulnerabilities.append(message)

    def crawl(self) -> list[str]:
        """Explore le site en largeur, jusqu'à `max_pages`, et scanne chaque page visitée."""
        urls_to_visit = [self.config.target_domain]

        while urls_to_visit and len(self.visited_urls) < self.config.max_pages:
            current_url = urls_to_visit.pop(0)
            if current_url in self.visited_urls:
                continue

            self.visited_urls.add(current_url)
            logger.info("Scan de %s (%d/%d)", current_url, len(self.visited_urls), self.config.max_pages)

            self.scan_page_for_redirects(current_url)
            self.scan_form_for_redirects(current_url)

            for link in self.get_all_links(current_url):
                full_link = urljoin(current_url, link)
                if same_site(full_link, self.target_netloc) and full_link not in self.visited_urls:
                    urls_to_visit.append(full_link)

            time.sleep(random.uniform(*self.config.delay_range))

        return self.vulnerabilities


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scanne un site web à la recherche de redirections ouvertes (open redirects).",
    )
    parser.add_argument("target", help="URL de base du site à scanner (ex : https://example.com)")
    parser.add_argument(
        "--external-url",
        default="https://evil.example.com",
        help="URL externe utilisée pour détecter une redirection ouverte (défaut : %(default)s)",
    )
    parser.add_argument(
        "--max-pages", type=int, default=100,
        help="Nombre maximum de pages à explorer (défaut : %(default)s)",
    )
    parser.add_argument(
        "--timeout", type=int, default=5,
        help="Timeout HTTP en secondes (défaut : %(default)s)",
    )
    parser.add_argument(
        "--min-delay", type=float, default=2.0,
        help="Délai minimum (s) entre deux pages (défaut : %(default)s)",
    )
    parser.add_argument(
        "--max-delay", type=float, default=5.0,
        help="Délai maximum (s) entre deux pages (défaut : %(default)s)",
    )
    parser.add_argument(
        "--output", default=None,
        help="Fichier dans lequel enregistrer les vulnérabilités trouvées",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Affiche les logs détaillés (pages sûres incluses)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(message)s",
    )

    config = ScanConfig(
        target_domain=args.target.rstrip("/"),
        external_url=args.external_url,
        max_pages=args.max_pages,
        timeout=args.timeout,
        delay_range=(args.min_delay, args.max_delay),
        output_file=args.output,
    )

    print(f"Scan de {config.target_domain} à la recherche de redirections ouvertes...\n")
    scanner = RedirectScanner(config)
    try:
        vulnerabilities = scanner.crawl()
    except KeyboardInterrupt:
        print("\nScan interrompu par l'utilisateur.")
        vulnerabilities = scanner.vulnerabilities

    print(f"\n{len(vulnerabilities)} redirection(s) ouverte(s) détectée(s) sur "
          f"{len(scanner.visited_urls)} page(s) explorée(s).")

    if config.output_file and vulnerabilities:
        with open(config.output_file, "w", encoding="utf-8") as f:
            f.write("\n".join(vulnerabilities))
        print(f"Résultats enregistrés dans {config.output_file}")

    return 1 if vulnerabilities else 0


if __name__ == "__main__":
    sys.exit(main())
