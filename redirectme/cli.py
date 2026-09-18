"""Menu interactif RedirectMe (rich + questionary)."""
from __future__ import annotations

import webbrowser
from pathlib import Path

import questionary
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from redirectme.config import AppConfig, ConfigError, load_config, save_config
from redirectme.profiles import list_profiles, load_profile, save_profile
from redirectme.report import ScanResult, generate_report
from redirectme.scanner import RedirectScanner

BANNER = """[bold cyan]╔══════════════════════════╗
║        RedirectMe        ║
║  Open Redirect Scanner   ║
╚══════════════════════════╝[/bold cyan]"""

MAIN_MENU_CHOICES = [
    "Lancer un scan",
    "Charger un profil de scan",
    "Configuration",
    "Voir le dernier rapport",
    "Quitter",
]


def run_interactive_menu(config_path: str = "config.ini") -> None:
    console = Console()
    config = load_config(config_path)
    last_report: Path | None = None

    while True:
        console.print(BANNER)
        choice = questionary.select("Que voulez-vous faire ?", choices=MAIN_MENU_CHOICES).ask()
        if choice is None or choice == "Quitter":
            console.print("[cyan]À bientôt ![/cyan]")
            return
        if choice == "Lancer un scan":
            report_path = _menu_launch_scan(console, config)
            if report_path:
                last_report = report_path
        elif choice == "Charger un profil de scan":
            config = _menu_load_profile(console, config)
        elif choice == "Configuration":
            config = _menu_configuration(console, config, config_path)
        elif choice == "Voir le dernier rapport":
            _menu_view_last_report(console, last_report)


def _menu_launch_scan(console: Console, config: AppConfig) -> Path | None:
    target = questionary.text(
        "URL cible à scanner (ex: https://example.com) :",
        validate=lambda text: bool(text)
        and (text.startswith("http://") or text.startswith("https://"))
        or "L'URL doit commencer par http:// ou https://",
    ).ask()
    if not target:
        return None

    table = Table(title="Options du scan")
    table.add_column("Option")
    table.add_column("Valeur")
    table.add_row("URL de redirection testée", config.external_url)
    table.add_row("Pages max", str(config.max_pages))
    table.add_row("Threads", str(config.max_workers))
    table.add_row("Payloads de contournement", "oui" if config.use_bypass_payloads else "non")
    table.add_row("Format de rapport", config.report_format)
    console.print(table)

    if not questionary.confirm("Utiliser ces options ?", default=True).ask():
        config = _edit_scan_options(config)

    authorized = questionary.confirm(
        f"Confirmez-vous être autorisé à tester {target} ?", default=False
    ).ask()
    if not authorized:
        console.print("[yellow]Scan annulé (autorisation non confirmée).[/yellow]")
        return None

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.fields[pages]} pages · {task.fields[vulns]} vulnérabilité(s)"),
        TimeElapsedColumn(),
        console=console,
    )

    state = {"pages": 0, "vulns": 0}
    result: ScanResult

    with progress:
        task_id = progress.add_task("Scan en cours...", pages=0, vulns=0)

        def on_progress(event: str, data: dict) -> None:
            if event == "page_scanned":
                state["pages"] = data["count"]
            elif event == "vulnerability_found":
                state["vulns"] += 1
            progress.update(task_id, pages=state["pages"], vulns=state["vulns"])

        scanner = RedirectScanner(target, config, on_progress=on_progress)
        try:
            result = scanner.crawl()
        except KeyboardInterrupt:
            result = scanner.result()
            console.print("[yellow]Scan interrompu.[/yellow]")

    _print_summary(console, result)
    report_path = generate_report(result, config.report_format, config.report_output_dir)
    console.print(f"[green]Rapport enregistré dans {report_path}[/green]")

    if report_path.suffix == ".html" and questionary.confirm(
        "Ouvrir le rapport dans le navigateur ?", default=True
    ).ask():
        webbrowser.open(report_path.resolve().as_uri())

    if questionary.confirm("Sauvegarder ces réglages comme profil ?", default=False).ask():
        name = questionary.text("Nom du profil :").ask()
        if name:
            save_profile(name, config)
            console.print(f"[green]Profil '{name}' sauvegardé.[/green]")

    return report_path


def _print_summary(console: Console, result: ScanResult) -> None:
    table = Table(title="Résumé du scan")
    table.add_column("Statut")
    table.add_column("URL")
    table.add_column("Détail")
    for vuln in result.vulnerabilities:
        table.add_row("[red]VULNÉRABLE[/red]", vuln.url, vuln.detail)
    if not result.vulnerabilities:
        table.add_row("[green]SÛR[/green]", result.target, "Aucune redirection ouverte détectée")
    console.print(table)
    console.print(
        f"{len(result.vulnerabilities)} redirection(s) ouverte(s) sur {result.pages_scanned} "
        f"page(s) explorée(s) en {result.duration_s:.1f}s."
    )


def _edit_scan_options(config: AppConfig) -> AppConfig:
    config.external_url = (
        questionary.text("URL de redirection testée :", default=config.external_url).ask()
        or config.external_url
    )
    config.max_pages = int(
        questionary.text("Pages max :", default=str(config.max_pages)).ask() or config.max_pages
    )
    config.max_workers = int(
        questionary.text("Threads :", default=str(config.max_workers)).ask()
        or config.max_workers
    )
    config.use_bypass_payloads = questionary.confirm(
        "Activer les payloads de contournement ?", default=config.use_bypass_payloads
    ).ask()
    config.report_format = questionary.select(
        "Format de rapport :", choices=["html", "txt", "json", "csv"], default=config.report_format
    ).ask()
    return config


def _menu_load_profile(console: Console, config: AppConfig) -> AppConfig:
    profiles = list_profiles()
    if not profiles:
        console.print("[yellow]Aucun profil sauvegardé.[/yellow]")
        return config
    name = questionary.select("Choisissez un profil :", choices=profiles + ["Annuler"]).ask()
    if not name or name == "Annuler":
        return config
    loaded = load_profile(name)
    console.print(f"[green]Profil '{name}' chargé.[/green]")
    return loaded


def _menu_configuration(console: Console, config: AppConfig, config_path: str) -> AppConfig:
    console.print("[bold]Configuration actuelle[/bold]")
    config = _edit_scan_options(config)
    config.timeout = int(
        questionary.text("Timeout HTTP (s) :", default=str(config.timeout)).ask()
        or config.timeout
    )
    config.min_delay = float(
        questionary.text("Délai minimum (s) :", default=str(config.min_delay)).ask()
        or config.min_delay
    )
    config.max_delay = float(
        questionary.text("Délai maximum (s) :", default=str(config.max_delay)).ask()
        or config.max_delay
    )
    config.respect_robots = questionary.confirm(
        "Respecter robots.txt ?", default=config.respect_robots
    ).ask()
    try:
        save_config(config, config_path)
        console.print("[green]Configuration sauvegardée.[/green]")
    except ConfigError as exc:
        console.print(f"[red]Erreur de configuration : {exc}[/red]")
    return config


def _menu_view_last_report(console: Console, last_report: Path | None) -> None:
    if not last_report:
        console.print("[yellow]Aucun rapport généré durant cette session.[/yellow]")
        return
    console.print(f"Dernier rapport : {last_report}")
    if last_report.suffix == ".html" and questionary.confirm(
        "Ouvrir dans le navigateur ?", default=True
    ).ask():
        webbrowser.open(last_report.resolve().as_uri())
