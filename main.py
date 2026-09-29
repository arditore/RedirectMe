#!/usr/bin/env python3
"""RedirectMe - open redirect scanner."""
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
        description="Scans a website for open redirects.",
    )
    parser.add_argument(
        "target", nargs="?", help="Base URL of the site to scan (e.g.: https://example.com)"
    )
    parser.add_argument(
        "--no-interactive", action="store_true", help="Force CLI mode (no interactive menu)"
    )
    parser.add_argument(
        "--yes", action="store_true", help="Automatically confirm scan authorization"
    )
    parser.add_argument(
        "--config", default="config.ini", help="Path to the config.ini file (default: %(default)s)"
    )
    parser.add_argument("--external-url", default=None, help="Override the external test URL")
    parser.add_argument("--max-pages", type=int, default=None, help="Override the max number of pages")
    parser.add_argument(
        "--output-format",
        choices=sorted(SUPPORTED_REPORT_FORMATS),
        default=None,
        help="Override the report format",
    )
    parser.add_argument("--output-dir", default=None, help="Override the report output directory")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed logs")
    return parser.parse_args(argv)


def run_cli(args: argparse.Namespace) -> int:
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING, format="%(message)s"
    )

    if not (args.target.startswith("http://") or args.target.startswith("https://")):
        print(
            f"Error: the target URL must start with http:// or https:// (got: {args.target!r}).",
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
        confirm = input(f"Are you authorized to scan {args.target}? (y/N) ").strip().lower()
        if confirm != "y":
            print("Scan cancelled (authorization not confirmed).")
            return 1

    print(f"🐧 noot noot — scanning {args.target} for open redirects...\n")
    scanner = RedirectScanner(args.target, config)
    try:
        result = scanner.crawl()
    except KeyboardInterrupt:
        print("\nScan interrupted by the user.")
        result = scanner.result()

    print(
        f"\n{len(result.vulnerabilities)} open redirect(s) detected across "
        f"{result.pages_scanned} page(s) scanned."
    )

    report_path = generate_report(result, config.report_format, config.report_output_dir)
    print(f"Report saved to {report_path}")

    if result.pages_scanned == 0:
        print(
            "Warning: no page could be scanned (target unreachable or blocked) — "
            "the scan did not actually happen.",
            file=sys.stderr,
        )
        return 3

    if result.vulnerabilities:
        print("🐧 Noot noot! The penguin found something.")
    else:
        print("🐧 Noot noot! Nothing to report, the ice floe is clean.")

    return 1 if result.vulnerabilities else 0


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    if args.target:
        return run_cli(args)

    if args.no_interactive:
        print("Error: --no-interactive requires a target URL.", file=sys.stderr)
        return 2

    run_interactive_menu(config_path=args.config)
    return 0


if __name__ == "__main__":
    sys.exit(main())
