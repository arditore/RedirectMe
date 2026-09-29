"""RedirectMe interactive menu (rich + questionary)."""
from __future__ import annotations

import copy
import random
import sys
import webbrowser
from pathlib import Path

import questionary
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from redirectme.config import AppConfig, load_config, save_config
from redirectme.profiles import (
    PROFILE_NAME_RE,
    InvalidProfileNameError,
    ProfileNotFoundError,
    list_profiles,
    load_profile,
    save_profile,
)
from redirectme.report import SUPPORTED_REPORT_FORMATS, ScanResult, generate_report
from redirectme.scanner import RedirectScanner

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

BANNER = r"""[bold cyan]      .--.
     |o_o |
     |:_/ |
    //   \ \
   (|     | )
  /'\_   _/`\
  \___)=(___/[/bold cyan]
[bold white]        noot noot 🐧[/bold white]
[bold cyan]╔══════════════════════════╗
║        RedirectMe        ║
║  Open Redirect Scanner   ║
╚══════════════════════════╝[/bold cyan]"""

FAREWELL_MESSAGES = [
    "[cyan]🐧 Noot noot, see you soon![/cyan]",
    "[cyan]🐧 The penguin waddles off elsewhere. See you soon![/cyan]",
    "[cyan]🐧 End of the ice floe for today. See you soon![/cyan]",
]

MAIN_MENU_CHOICES = [
    "Start a scan",
    "Load a scan profile",
    "Configuration",
    "View last report",
    "Quit",
]


def _validate_int(text: str) -> bool | str:
    if not text:
        return True
    try:
        int(text)
        return True
    except ValueError:
        return "Please enter a whole number."


def _validate_float(text: str) -> bool | str:
    if not text:
        return True
    try:
        float(text)
        return True
    except ValueError:
        return "Please enter a number."


def _truncate(text: str, max_len: int = 70) -> str:
    """Shortens `text` for a single-line progress display so a long test URL
    doesn't wrap or push the elapsed-time column off-screen."""
    if len(text) <= max_len:
        return text
    return text[: max_len - 1] + "…"


def _validate_profile_name(text: str) -> bool | str:
    # Must stay consistent with PROFILE_NAME_RE in redirectme/profiles.py.
    if text and PROFILE_NAME_RE.match(text):
        return True
    return "Profile names may only contain letters, digits, '-' and '_'."


def run_interactive_menu(config_path: str = "config.ini") -> None:
    console = Console()
    config = load_config(config_path)
    last_report: Path | None = None

    while True:
        console.print(BANNER)
        choice = questionary.select("🐧 What would you like to do?", choices=MAIN_MENU_CHOICES).ask()
        if choice is None or choice == "Quit":
            console.print(random.choice(FAREWELL_MESSAGES))
            return
        if choice == "Start a scan":
            report_path = _menu_launch_scan(console, config, config_path)
            if report_path:
                last_report = report_path
        elif choice == "Load a scan profile":
            config = _menu_load_profile(console, config)
        elif choice == "Configuration":
            config = _menu_configuration(console, config, config_path)
        elif choice == "View last report":
            _menu_view_last_report(console, last_report)


def _prompt_target_url() -> str | None:
    return questionary.text(
        "Target URL to scan (e.g.: https://example.com):",
        validate=lambda text: bool(text)
        and (text.startswith("http://") or text.startswith("https://"))
        or "The URL must start with http:// or https://",
    ).ask()


def _menu_launch_scan(console: Console, config: AppConfig, config_path: str) -> Path | None:
    if config.last_target:
        reuse = questionary.confirm(
            f"Scan {config.last_target} again?", default=True
        ).ask()
        if reuse is None:
            return None
        target = config.last_target if reuse else _prompt_target_url()
    else:
        target = _prompt_target_url()
    if not target:
        return None

    if target != config.last_target:
        config.last_target = target
        try:
            save_config(config, config_path)
        except OSError as exc:
            console.print(f"[yellow]Could not save the last target: {exc}[/yellow]")

    # Settings edited here are one-off (specific to this scan) and must not
    # change the persistent session configuration (see the "Configuration"
    # menu, which keeps working on `config`).
    scan_config = copy.deepcopy(config)

    table = Table(title="Scan options")
    table.add_column("Option")
    table.add_column("Value")
    table.add_row("Redirect URL under test", scan_config.external_url)
    table.add_row("Max pages", str(scan_config.max_pages))
    table.add_row("Threads", str(scan_config.max_workers))
    table.add_row(
        "Bypass payloads", "yes" if scan_config.use_bypass_payloads else "no"
    )
    table.add_row("Report format", scan_config.report_format)
    console.print(table)

    if not questionary.confirm("Use these options?", default=True).ask():
        scan_config = _edit_scan_options(scan_config)

    authorized = questionary.confirm(
        f"Are you authorized to test {target}?", default=False
    ).ask()
    if not authorized:
        console.print("[yellow]Scan cancelled (authorization not confirmed).[/yellow]")
        return None

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TextColumn("[dim]{task.fields[status]}[/dim]"),
        TimeElapsedColumn(),
        console=console,
    )

    state = {"pages": 0, "vulns": 0}
    result: ScanResult

    def _status_text() -> str:
        pages_word = "page" if state["pages"] == 1 else "pages"
        vulns_word = "vulnerability" if state["vulns"] == 1 else "vulnerabilities"
        return f"{state['pages']} {pages_word} · {state['vulns']} {vulns_word}"

    with progress:
        task_id = progress.add_task("🐧 Starting scan...", status=_status_text())

        def on_progress(event: str, data: dict) -> None:
            if event == "page_scanned":
                state["pages"] = data["count"]
                progress.update(task_id, description=f"🐧 Scanning {_truncate(data['url'])}")
            elif event == "link_tested":
                progress.update(task_id, description=f"🐧 Testing {_truncate(data['url'])}")
            elif event == "vulnerability_found":
                state["vulns"] += 1
            progress.update(task_id, status=_status_text())

        scanner = RedirectScanner(target, scan_config, on_progress=on_progress)
        try:
            result = scanner.crawl()
        except KeyboardInterrupt:
            result = scanner.result()
            console.print("[yellow]Scan interrupted.[/yellow]")

    _print_summary(console, result)
    report_path = generate_report(result, scan_config.report_format, scan_config.report_output_dir)
    console.print(f"[green]Report saved to {report_path}[/green]")

    if report_path.suffix == ".html" and questionary.confirm(
        "Open the report in the browser?", default=True
    ).ask():
        webbrowser.open(report_path.resolve().as_uri())

    if questionary.confirm("Save these settings as a profile?", default=False).ask():
        name = questionary.text("Profile name:", validate=_validate_profile_name).ask()
        if name:
            try:
                save_profile(name, scan_config)
                console.print(f"[green]Profile '{name}' saved.[/green]")
            except InvalidProfileNameError as exc:
                console.print(f"[red]Invalid profile name: {exc}[/red]")

    return report_path


def _print_summary(console: Console, result: ScanResult) -> None:
    table = Table(title="Scan summary")
    table.add_column("Status")
    table.add_column("URL")
    table.add_column("Detail")
    for vuln in result.vulnerabilities:
        table.add_row("[red]VULNERABLE[/red]", vuln.url, vuln.detail)
    if not result.vulnerabilities:
        table.add_row("[green]SAFE[/green]", result.target, "No open redirect detected")
    console.print(table)
    console.print(
        f"{len(result.vulnerabilities)} open redirect(s) across {result.pages_scanned} "
        f"page(s) scanned in {result.duration_s:.1f}s."
    )
    if result.vulnerabilities:
        console.print("[red]🐧 Noot noot! The penguin found something.[/red]")
    else:
        console.print("[green]🐧 Noot noot! Nothing to report, the ice floe is clean.[/green]")


def _edit_scan_options(config: AppConfig) -> AppConfig:
    config.external_url = (
        questionary.text("Redirect URL under test:", default=config.external_url).ask()
        or config.external_url
    )
    config.max_pages = int(
        questionary.text(
            "Max pages:", default=str(config.max_pages), validate=_validate_int
        ).ask()
        or config.max_pages
    )
    config.max_workers = int(
        questionary.text(
            "Threads:", default=str(config.max_workers), validate=_validate_int
        ).ask()
        or config.max_workers
    )
    use_bypass_answer = questionary.confirm(
        "Enable bypass payloads?", default=config.use_bypass_payloads
    ).ask()
    config.use_bypass_payloads = (
        use_bypass_answer if use_bypass_answer is not None else config.use_bypass_payloads
    )
    report_format_answer = questionary.select(
        "Report format:",
        choices=sorted(SUPPORTED_REPORT_FORMATS),
        default=config.report_format,
    ).ask()
    config.report_format = (
        report_format_answer if report_format_answer is not None else config.report_format
    )
    return config


def _menu_load_profile(console: Console, config: AppConfig) -> AppConfig:
    profiles = list_profiles()
    if not profiles:
        console.print("[yellow]No saved profiles.[/yellow]")
        return config
    name = questionary.select("Choose a profile:", choices=profiles + ["Cancel"]).ask()
    if not name or name == "Cancel":
        return config
    try:
        loaded = load_profile(name)
    except (ProfileNotFoundError, InvalidProfileNameError) as exc:
        console.print(f"[red]Profile not found or invalid: {exc}[/red]")
        return config
    console.print(f"[green]Profile '{name}' loaded.[/green]")
    return loaded


def _menu_configuration(console: Console, config: AppConfig, config_path: str) -> AppConfig:
    console.print("[bold]Current configuration[/bold]")
    config = _edit_scan_options(config)
    config.timeout = int(
        questionary.text(
            "HTTP timeout (s):", default=str(config.timeout), validate=_validate_int
        ).ask()
        or config.timeout
    )
    config.min_delay = float(
        questionary.text(
            "Minimum delay (s):", default=str(config.min_delay), validate=_validate_float
        ).ask()
        or config.min_delay
    )
    config.max_delay = float(
        questionary.text(
            "Maximum delay (s):", default=str(config.max_delay), validate=_validate_float
        ).ask()
        or config.max_delay
    )
    respect_robots_answer = questionary.confirm(
        "Respect robots.txt?", default=config.respect_robots
    ).ask()
    config.respect_robots = (
        respect_robots_answer if respect_robots_answer is not None else config.respect_robots
    )
    try:
        save_config(config, config_path)
        console.print("[green]Configuration saved.[/green]")
    except OSError as exc:
        # save_config performs no validation (ConfigError comes from load_config);
        # the realistic failure here is a disk write issue (permissions, a
        # read-only path...).
        console.print(f"[red]Could not save the configuration: {exc}[/red]")
    return config


def _menu_view_last_report(console: Console, last_report: Path | None) -> None:
    if not last_report:
        console.print("[yellow]No report generated during this session.[/yellow]")
        return
    console.print(f"Last report: {last_report}")
    if last_report.suffix == ".html" and questionary.confirm(
        "Open in the browser?", default=True
    ).ask():
        webbrowser.open(last_report.resolve().as_uri())
