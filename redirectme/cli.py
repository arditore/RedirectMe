"""Menu interactif RedirectMe (rich + questionary)."""
from __future__ import annotations

import copy
import random
import sys
import webbrowser
from pathlib import Path

import questionary
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
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
    "[cyan]🐧 Noot noot, à bientôt ![/cyan]",
    "[cyan]🐧 Le pingouin s'en va se dandiner ailleurs. À bientôt ![/cyan]",
    "[cyan]🐧 Fin de la banquise pour aujourd'hui. À bientôt ![/cyan]",
]

MAIN_MENU_CHOICES = [
    "Lancer un scan",
    "Charger un profil de scan",
    "Configuration",
    "Voir le dernier rapport",
    "Quitter",
]


def _validate_int(text: str) -> bool | str:
    if not text:
        return True
    try:
        int(text)
        return True
    except ValueError:
        return "Merci d'entrer un nombre entier."


def _validate_float(text: str) -> bool | str:
    if not text:
        return True
    try:
        float(text)
        return True
    except ValueError:
        return "Merci d'entrer un nombre."


def _validate_profile_name(text: str) -> bool | str:
    # Doit rester cohérent avec PROFILE_NAME_RE de redirectme/profiles.py.
    if text and PROFILE_NAME_RE.match(text):
        return True
    return "Le nom du profil ne doit contenir que des lettres, chiffres, '-' et '_'."


def run_interactive_menu(config_path: str = "config.ini") -> None:
    console = Console()
    config = load_config(config_path)
    last_report: Path | None = None

    while True:
        console.print(BANNER)
        choice = questionary.select("🐧 Que voulez-vous faire ?", choices=MAIN_MENU_CHOICES).ask()
        if choice is None or choice == "Quitter":
            console.print(random.choice(FAREWELL_MESSAGES))
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

    # Les réglages édités ici sont ponctuels (propres à ce scan) et ne doivent
    # pas modifier la configuration persistante de la session (cf. menu
    # "Configuration", qui lui reste sur `config`).
    scan_config = copy.deepcopy(config)

    table = Table(title="Options du scan")
    table.add_column("Option")
    table.add_column("Valeur")
    table.add_row("URL de redirection testée", scan_config.external_url)
    table.add_row("Pages max", str(scan_config.max_pages))
    table.add_row("Threads", str(scan_config.max_workers))
    table.add_row(
        "Payloads de contournement", "oui" if scan_config.use_bypass_payloads else "non"
    )
    table.add_row("Format de rapport", scan_config.report_format)
    console.print(table)

    if not questionary.confirm("Utiliser ces options ?", default=True).ask():
        scan_config = _edit_scan_options(scan_config)

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
        task_id = progress.add_task("🐧 Scan en cours (noot noot)...", pages=0, vulns=0)

        def on_progress(event: str, data: dict) -> None:
            if event == "page_scanned":
                state["pages"] = data["count"]
            elif event == "vulnerability_found":
                state["vulns"] += 1
            progress.update(task_id, pages=state["pages"], vulns=state["vulns"])

        scanner = RedirectScanner(target, scan_config, on_progress=on_progress)
        try:
            result = scanner.crawl()
        except KeyboardInterrupt:
            result = scanner.result()
            console.print("[yellow]Scan interrompu.[/yellow]")

    _print_summary(console, result)
    report_path = generate_report(result, scan_config.report_format, scan_config.report_output_dir)
    console.print(f"[green]Rapport enregistré dans {report_path}[/green]")

    if report_path.suffix == ".html" and questionary.confirm(
        "Ouvrir le rapport dans le navigateur ?", default=True
    ).ask():
        webbrowser.open(report_path.resolve().as_uri())

    if questionary.confirm("Sauvegarder ces réglages comme profil ?", default=False).ask():
        name = questionary.text("Nom du profil :", validate=_validate_profile_name).ask()
        if name:
            try:
                save_profile(name, scan_config)
                console.print(f"[green]Profil '{name}' sauvegardé.[/green]")
            except InvalidProfileNameError as exc:
                console.print(f"[red]Nom de profil invalide : {exc}[/red]")

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
    if result.vulnerabilities:
        console.print("[red]🐧 Noot noot ! Le pingouin a trouvé quelque chose.[/red]")
    else:
        console.print("[green]🐧 Noot noot ! Rien à signaler, la banquise est saine.[/green]")


def _edit_scan_options(config: AppConfig) -> AppConfig:
    config.external_url = (
        questionary.text("URL de redirection testée :", default=config.external_url).ask()
        or config.external_url
    )
    config.max_pages = int(
        questionary.text(
            "Pages max :", default=str(config.max_pages), validate=_validate_int
        ).ask()
        or config.max_pages
    )
    config.max_workers = int(
        questionary.text(
            "Threads :", default=str(config.max_workers), validate=_validate_int
        ).ask()
        or config.max_workers
    )
    use_bypass_answer = questionary.confirm(
        "Activer les payloads de contournement ?", default=config.use_bypass_payloads
    ).ask()
    config.use_bypass_payloads = (
        use_bypass_answer if use_bypass_answer is not None else config.use_bypass_payloads
    )
    report_format_answer = questionary.select(
        "Format de rapport :",
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
        console.print("[yellow]Aucun profil sauvegardé.[/yellow]")
        return config
    name = questionary.select("Choisissez un profil :", choices=profiles + ["Annuler"]).ask()
    if not name or name == "Annuler":
        return config
    try:
        loaded = load_profile(name)
    except (ProfileNotFoundError, InvalidProfileNameError) as exc:
        console.print(f"[red]Profil introuvable ou invalide : {exc}[/red]")
        return config
    console.print(f"[green]Profil '{name}' chargé.[/green]")
    return loaded


def _menu_configuration(console: Console, config: AppConfig, config_path: str) -> AppConfig:
    console.print("[bold]Configuration actuelle[/bold]")
    config = _edit_scan_options(config)
    config.timeout = int(
        questionary.text(
            "Timeout HTTP (s) :", default=str(config.timeout), validate=_validate_int
        ).ask()
        or config.timeout
    )
    config.min_delay = float(
        questionary.text(
            "Délai minimum (s) :", default=str(config.min_delay), validate=_validate_float
        ).ask()
        or config.min_delay
    )
    config.max_delay = float(
        questionary.text(
            "Délai maximum (s) :", default=str(config.max_delay), validate=_validate_float
        ).ask()
        or config.max_delay
    )
    respect_robots_answer = questionary.confirm(
        "Respecter robots.txt ?", default=config.respect_robots
    ).ask()
    config.respect_robots = (
        respect_robots_answer if respect_robots_answer is not None else config.respect_robots
    )
    try:
        save_config(config, config_path)
        console.print("[green]Configuration sauvegardée.[/green]")
    except OSError as exc:
        # save_config ne valide rien (ConfigError vient de load_config) ; l'échec
        # réaliste ici est un problème d'écriture disque (permissions, chemin en lecture
        # seule...).
        console.print(f"[red]Impossible d'enregistrer la configuration : {exc}[/red]")
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
