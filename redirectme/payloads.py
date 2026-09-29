"""Known redirect parameters and bypass payloads."""
from __future__ import annotations

from urllib.parse import urlsplit

DEFAULT_REDIRECT_PARAMS = [
    "url", "redirect", "next", "return", "to", "continue", "redirect_uri",
    "target", "destination", "goto", "next_url", "post_login_redirect",
    "continue_url", "after_login", "forward_to", "landing", "next_page",
    "path", "jump", "ref", "redir", "callback", "referred_by", "from", "link",
]


def build_payloads(
    param: str, target_host: str, external_url: str, use_bypass: bool = True
) -> list[str]:
    """Returns the values to test for `param` in order to detect an open redirect."""
    external_host = urlsplit(external_url).netloc or external_url
    values = [external_url]
    if use_bypass:
        values.extend(
            [
                f"//{external_host}",
                f"/\\{external_host}",
                f"https:{external_url}",
                f"{target_host}@{external_host}",
                f"%2F%2F{external_host}",
            ]
        )
    return values
