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
                # target as a subdomain label of the attacker's host: fools a naive
                # `location.startswith(target_host)`/`target_host in location` check
                # even though the real, navigable host is external_host.
                f"https://{target_host}.{external_host}",
                # target as a path segment after the attacker's host: same class of
                # naive substring-check bypass, from the other direction.
                f"https://{external_host}/{target_host}",
                # double URL-encoded protocol-relative: catches an app that only
                # sanitizes the once-decoded value but reflects a twice-decoded one.
                f"%252F%252F{external_host}",
                # leading tab: per the URL spec, browsers strip tab/newline/CR
                # anywhere in a URL, so this still resolves to the attacker's host
                # while evading a regex filter anchored on "//" at position 0.
                f"\t//{external_host}",
                # missing slashes after the scheme: some parsers normalize this to
                # a proper "scheme://" (as browsers do for special schemes).
                f"https:{external_host}",
            ]
        )
    return values
