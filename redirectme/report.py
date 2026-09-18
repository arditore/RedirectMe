"""Génération de rapports de scan (TXT / JSON / CSV / HTML)."""
from __future__ import annotations

import csv
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
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    timestamp = result.started_at.strftime("%Y%m%d-%H%M%S")
    path = directory / f"redirectme-{timestamp}.{fmt}"

    writers = {
        "txt": _write_txt,
        "json": _write_json,
        "csv": _write_csv,
        "html": _write_html,
    }
    writer = writers.get(fmt)
    if writer is None:
        raise UnsupportedFormatError(f"Format de rapport non supporté : {fmt}")
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


def _write_csv(result: ScanResult, path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["type", "url", "detail"])
        for vuln in result.vulnerabilities:
            writer.writerow([vuln.type, vuln.url, vuln.detail])


def _write_html(result: ScanResult, path: Path) -> None:
    rows = "\n".join(
        f"<tr><td class='vuln'>VULNÉRABLE</td><td>{v.type}</td><td>{v.url}</td><td>{v.detail}</td></tr>"
        for v in result.vulnerabilities
    ) or "<tr><td colspan='4'>Aucune redirection ouverte détectée.</td></tr>"

    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<title>Rapport RedirectMe - {result.target}</title>
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
<p class="summary">Cible : {result.target}<br>
Date : {result.started_at.isoformat()}<br>
Durée : {result.duration_s:.1f}s &middot; Pages explorées : {result.pages_scanned} &middot;
Vulnérabilités : {len(result.vulnerabilities)}</p>
<table>
<tr><th>Statut</th><th>Type</th><th>URL</th><th>Détail</th></tr>
{rows}
</table>
</body>
</html>"""
    path.write_text(html, encoding="utf-8")
