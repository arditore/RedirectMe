"""Génération de rapports de scan (TXT / JSON / CSV / HTML)."""
from __future__ import annotations

import csv
import html
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


@dataclass
class Vulnerability:
    type: str
    url: str
    detail: str


@dataclass
class ScanResult:
    target: str
    started_at: datetime
    duration_s: float
    pages_scanned: int
    vulnerabilities: list[Vulnerability] = field(default_factory=list)


class UnsupportedFormatError(ValueError):
    """Levée quand le format de rapport demandé n'est pas supporté."""


def generate_report(result: ScanResult, fmt: str, output_dir: str = "reports") -> Path:
    fmt = fmt.lower()
    writer = _WRITERS.get(fmt)
    if writer is None:
        raise UnsupportedFormatError(f"Format de rapport non supporté : {fmt}")

    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    timestamp = result.started_at.strftime("%Y%m%d-%H%M%S")
    path = directory / f"redirectme-{timestamp}.{fmt}"
    writer(result, path)
    return path


def _write_txt(result: ScanResult, path: Path) -> None:
    lines = [
        f"Cible : {result.target}",
        f"Date : {result.started_at.isoformat()}",
        f"Durée : {result.duration_s:.1f}s",
        f"Pages explorées : {result.pages_scanned}",
        "",
    ]
    if result.vulnerabilities:
        for vuln in result.vulnerabilities:
            lines.append(f"[VULNÉRABLE] {vuln.url} ({vuln.type}) - {vuln.detail}")
    else:
        lines.append("Aucune redirection ouverte détectée.")
    path.write_text("\n".join(lines), encoding="utf-8")


def _write_json(result: ScanResult, path: Path) -> None:
    payload = {
        "target": result.target,
        "started_at": result.started_at.isoformat(),
        "duration_s": result.duration_s,
        "pages_scanned": result.pages_scanned,
        "vulnerabilities": [
            {"type": v.type, "url": v.url, "detail": v.detail} for v in result.vulnerabilities
        ],
    }
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe(value: str) -> str:
    """Neutralise l'injection de formule CSV (valeur issue du site scanné, non fiable) :
    un champ commençant par =, +, -, @ ou une tabulation/retour chariot est interprété comme
    une formule par Excel/Sheets à l'ouverture. On le préfixe d'un guillemet simple pour le
    forcer en texte, comme le recommande l'OWASP."""
    if value.startswith(_CSV_FORMULA_PREFIXES):
        return "'" + value
    return value


def _write_csv(result: ScanResult, path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["type", "url", "detail"])
        for vuln in result.vulnerabilities:
            writer.writerow(
                [_csv_safe(vuln.type), _csv_safe(vuln.url), _csv_safe(vuln.detail)]
            )


def _write_html(result: ScanResult, path: Path) -> None:
    rows = "\n".join(
        f"<tr><td class='vuln'>VULNÉRABLE</td><td>{html.escape(v.type)}</td><td>{html.escape(v.url)}</td><td>{html.escape(v.detail)}</td></tr>"
        for v in result.vulnerabilities
    ) or "<tr><td colspan='4'>Aucune redirection ouverte détectée.</td></tr>"

    html_content = f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<title>Rapport RedirectMe - {html.escape(result.target)}</title>
<style>
body {{ font-family: system-ui, sans-serif; background: #0f172a; color: #e2e8f0; padding: 2rem; }}
h1 {{ color: #38bdf8; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; }}
th, td {{ padding: 0.5rem 0.75rem; border-bottom: 1px solid #334155; text-align: left; }}
th {{ color: #94a3b8; text-transform: uppercase; font-size: 0.8rem; }}
.vuln {{ color: #f87171; font-weight: bold; }}
.summary {{ color: #94a3b8; }}
</style>
</head>
<body>
<h1>Rapport RedirectMe</h1>
<p class="summary">Cible : {html.escape(result.target)}<br>
Date : {result.started_at.isoformat()}<br>
Durée : {result.duration_s:.1f}s &middot; Pages explorées : {result.pages_scanned} &middot;
Vulnérabilités : {len(result.vulnerabilities)}</p>
<table>
<tr><th>Statut</th><th>Type</th><th>URL</th><th>Détail</th></tr>
{rows}
</table>
</body>
</html>"""
    path.write_text(html_content, encoding="utf-8")


_WRITERS = {
    "txt": _write_txt,
    "json": _write_json,
    "csv": _write_csv,
    "html": _write_html,
}

# Source unique de vérité pour les formats de rapport supportés : consommée par
# redirectme.config (validation de config.ini), main.py et redirectme.cli (choix
# proposés) pour éviter que la liste ne diverge de ce que ce module sait réellement écrire.
SUPPORTED_REPORT_FORMATS = frozenset(_WRITERS)
