from datetime import datetime

import main
from main import parse_args, run_cli
from redirectme.report import ScanResult


def test_parse_args_defaults():
    args = parse_args(["https://example.com"])
    assert args.target == "https://example.com"
    assert args.no_interactive is False
    assert args.yes is False
    assert args.config == "config.ini"


def test_run_cli_cancels_without_confirmation(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    args = parse_args(["https://example.com"])
    monkeypatch.setattr("builtins.input", lambda prompt: "n")

    exit_code = run_cli(args)

    assert exit_code == 1
    assert "cancelled" in capsys.readouterr().out.lower()


def test_run_cli_rejects_scheme_less_target(tmp_path, monkeypatch, capsys):
    # Regression test for Finding 7: a target with no http(s):// scheme used to
    # silently "succeed" (every request raised MissingSchema internally, so the
    # scan fetched 0 pages and still exited 0). It must now be rejected
    # immediately, before even asking for scan authorization, with a non-zero
    # exit code. `--yes` is passed so a hang on `input()` would prove the
    # rejection did NOT happen early (mirrors the existing cancel-path test's
    # no-network-mocking approach: nothing here should construct a scanner).
    monkeypatch.chdir(tmp_path)
    args = parse_args(["example.com", "--yes"])
    monkeypatch.setattr(
        "builtins.input", lambda prompt: (_ for _ in ()).throw(AssertionError("should not prompt"))
    )

    exit_code = run_cli(args)

    assert exit_code != 0
    captured = capsys.readouterr()
    assert "http://" in captured.err.lower() or "https://" in captured.err.lower()


def test_run_cli_returns_distinct_exit_code_when_no_pages_scanned(tmp_path, monkeypatch, capsys):
    # Regression test for Finding 7's second layer: even with a valid scheme,
    # a scan that fetched 0 pages (target unreachable, DNS failure, etc.) must
    # never report success (exit 0) or be conflated with "0 vulnerabilities
    # found" (exit 0 via `1 if vulnerabilities else 0`).
    monkeypatch.chdir(tmp_path)
    args = parse_args(["https://example.com", "--yes"])

    class FakeScanner:
        def __init__(self, target, config, on_progress=None):
            pass

        def crawl(self):
            return ScanResult(
                target="https://example.com",
                started_at=datetime.now(),
                duration_s=0.1,
                pages_scanned=0,
                vulnerabilities=[],
            )

    monkeypatch.setattr(main, "RedirectScanner", FakeScanner)

    exit_code = run_cli(args)

    assert exit_code == 3
    out = capsys.readouterr()
    assert "no page" in (out.out + out.err).lower()
