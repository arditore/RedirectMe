from redirectme.payloads import DEFAULT_REDIRECT_PARAMS, build_payloads


def test_build_payloads_without_bypass_returns_only_raw_url():
    values = build_payloads("url", "example.com", "https://evil.example.com", use_bypass=False)
    assert values == ["https://evil.example.com"]


def test_build_payloads_with_bypass_includes_known_variants():
    values = build_payloads("url", "example.com", "https://evil.example.com", use_bypass=True)
    assert values == [
        "https://evil.example.com",
        "//evil.example.com",
        "/\\evil.example.com",
        "https:https://evil.example.com",
        "example.com@evil.example.com",
        "%2F%2Fevil.example.com",
        "https://example.com.evil.example.com",
        "https://evil.example.com/example.com",
        "%252F%252Fevil.example.com",
        "\t//evil.example.com",
        "https:evil.example.com",
    ]


def test_default_redirect_params_has_no_duplicates():
    assert len(DEFAULT_REDIRECT_PARAMS) == len(set(DEFAULT_REDIRECT_PARAMS))
