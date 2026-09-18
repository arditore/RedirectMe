from main import parse_args, run_cli


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
    assert "annulé" in capsys.readouterr().out.lower()
