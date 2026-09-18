import csv
import json
from datetime import datetime

import pytest

from redirectme.report import ScanResult, UnsupportedFormatError, Vulnerability, generate_report


def make_result() -> ScanResult:
    return ScanResult(
        target="https://example.com",
        started_at=datetime(2026, 9, 18, 10, 30, 0),
        duration_s=12.5,
        pages_scanned=3,
        vulnerabilities=[
            Vulnerability(
                type="param",
                url="https://example.com/a?url=https://evil.example.com",
                detail="url=https://evil.example.com",
            ),
        ],
    )


def test_generate_txt_report(tmp_path):
    path = generate_report(make_result(), "txt", str(tmp_path))
    content = path.read_text(encoding="utf-8")
    assert "https://example.com" in content
    assert "VULNÉRABLE" in content


def test_generate_json_report(tmp_path):
    path = generate_report(make_result(), "json", str(tmp_path))
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["target"] == "https://example.com"
    assert data["pages_scanned"] == 3
    assert len(data["vulnerabilities"]) == 1
    assert data["vulnerabilities"][0]["type"] == "param"


def test_generate_csv_report(tmp_path):
    path = generate_report(make_result(), "csv", str(tmp_path))
    with path.open(encoding="utf-8") as f:
        rows = list(csv.reader(f))
    assert rows[0] == ["type", "url", "detail"]
    assert rows[1][0] == "param"


def test_generate_html_report(tmp_path):
    path = generate_report(make_result(), "html", str(tmp_path))
    content = path.read_text(encoding="utf-8")
    assert "<html" in content
    assert "https://example.com/a?url=https://evil.example.com" in content


def test_generate_report_rejects_unsupported_format(tmp_path):
    with pytest.raises(UnsupportedFormatError):
        generate_report(make_result(), "pdf", str(tmp_path))


def test_html_report_escapes_xss_payload_in_url(tmp_path):
    """Test that XSS payloads in URL are properly escaped to prevent stored XSS."""
    xss_payload = "<script>alert(1)</script>"
    result = ScanResult(
        target="https://example.com",
        started_at=datetime(2026, 9, 18, 10, 30, 0),
        duration_s=12.5,
        pages_scanned=3,
        vulnerabilities=[
            Vulnerability(
                type="param",
                url=f"https://example.com?url={xss_payload}",
                detail="test detail",
            ),
        ],
    )
    path = generate_report(result, "html", str(tmp_path))
    content = path.read_text(encoding="utf-8")

    # Assert that unescaped payload does NOT appear in the HTML
    assert xss_payload not in content
    # Assert that escaped form DOES appear
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in content


def test_html_report_escapes_xss_payload_in_detail(tmp_path):
    """Test that XSS payloads in detail are properly escaped to prevent stored XSS."""
    xss_payload = "<img src=x onerror=alert('xss')>"
    result = ScanResult(
        target="https://example.com",
        started_at=datetime(2026, 9, 18, 10, 30, 0),
        duration_s=12.5,
        pages_scanned=3,
        vulnerabilities=[
            Vulnerability(
                type="param",
                url="https://example.com/page",
                detail=xss_payload,
            ),
        ],
    )
    path = generate_report(result, "html", str(tmp_path))
    content = path.read_text(encoding="utf-8")

    # Assert that unescaped payload does NOT appear in the HTML
    assert xss_payload not in content
    # Assert that escaped form DOES appear
    assert "&lt;img src=x onerror=alert(&#x27;xss&#x27;)&gt;" in content


def test_html_report_escapes_xss_payload_in_target(tmp_path):
    """Test that XSS payloads in target are properly escaped to prevent stored XSS."""
    xss_payload = "https://example.com<svg onload=alert(1)>"
    result = ScanResult(
        target=xss_payload,
        started_at=datetime(2026, 9, 18, 10, 30, 0),
        duration_s=12.5,
        pages_scanned=3,
        vulnerabilities=[],
    )
    path = generate_report(result, "html", str(tmp_path))
    content = path.read_text(encoding="utf-8")

    # Assert that unescaped payload does NOT appear in the HTML
    assert xss_payload not in content
    # Assert that escaped form DOES appear in both title and summary
    assert "&lt;svg onload=alert(1)&gt;" in content
