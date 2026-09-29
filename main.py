#!/usr/bin/env python3
"""RedirectMe - scanner de redirections ouvertes (open redirect)."""
from __future__ import annotations

import argparse
import logging
import sys

from redirectme.cli import run_interactive_menu
from redirectme.config import load_config
from redirectme.report import SUPPORTED_REPORT_FORMATS, generate_report
from redirectme.scanner import RedirectScanner


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scanne un site web à la recherche de redirections ouvertes (open redirects).",
    )
    parser.add_argument(
        "target", nargs="?", help="URL de base du site à scanner (ex : https://example.com)"
    )
    parser.add_argument(
        "--no-interactive", action="store_true", help="Force le mode CLI (sans menu interactif)"
    )
    parser.add_argument(
        "--yes", action="store_true", help="Confirme automatiquement l'autorisation de scan"
    )
    parser.add_argument(
        "--config", default="config.ini", help="Chemin du fichier config.ini (défaut : %(default)s)"
    )
    parser.add_argument("--external-url", default=None, help="Surcharge l'URL externe de test")
    parser.add_argument("--max-pages", type=int, default=None, help="Surcharge le nombre max de pages")
    parser.add_argument(
        "--output-format",
        choices=sorted(SUPPORTED_REPORT_FORMATS),
        default=None,
        help="Surcharge le format de rapport",
    )
    parser.add_argument("--output-dir", default=None, help="Surcharge le dossier de sortie des rapports")
    parser.add_argument("-v", "--verbose", action="store_true", help="Affiche les logs détaillés")
    return parser.parse_args(argv)


def run_cli(args: argparse.Namespace) -> int:
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING, format="%(message)s"
    )

    if not (args.target.startswith("http://") or args.target.startswith("https://")):
        print(
            f"Erreur : l'URL cible doit commencer par http:// ou https:// (reçu : {args.target!r}).",
            file=sys.stderr,
        )
        return 2

    config = load_config(args.config)
    if args.external_url:
        config.external_url = args.external_url
    if args.max_pages:
        config.max_pages = args.max_pages
    if args.output_format:
        config.report_format = args.output_format
    if args.output_dir:
        config.report_output_dir = args.output_dir

    if not args.yes:
        confirm = input(f"Confirmez-vous être autorisé à scanner {args.target} ? (o/N) ").strip().lower()
        if confirm != "o":
            print("Scan annulé (autorisation non confirmée).")
            return 1

    print(f"🐧 noot noot — scan de {args.target} à la recherche de redirections ouvertes...\n")
    scanner = RedirectScanner(args.target, config)
    try:
        result = scanner.crawl()
    except KeyboardInterrupt:
        print("\nScan interrompu par l'utilisateur.")
        result = scanner.result()

    print(
        f"\n{len(result.vulnerabilities)} redirection(s) ouverte(s) détectée(s) sur "
        f"{result.pages_scanned} page(s) explorée(s)."
    )

    report_path = generate_report(result, config.report_format, config.report_output_dir)
    print(f"Rapport enregistré dans {report_path}")

    if result.pages_scanned == 0:
        print(
            "Avertissement : aucune page n'a pu être scannée (cible injoignable ou "
            "bloquée) — le scan n'a pas réellement eu lieu.",
            file=sys.stderr,
        )
        return 3

    if result.vulnerabilities:
        print("🐧 Noot noot ! Le pingouin a trouvé quelque chose.")
    else:
        print("🐧 Noot noot ! Rien à signaler, la banquise est saine.")

    return 1 if result.vulnerabilities else 0


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    if args.target:
        return run_cli(args)

    if args.no_interactive:
        print("Erreur : --no-interactive nécessite une URL cible.", file=sys.stderr)
        return 2

    run_interactive_menu(config_path=args.config)
    return 0


if __name__ == "__main__":
    sys.exit(main())
