# Interface CLI interactive & fonctionnalités avancées — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Transformer `RedirectMe` (script unique `main.py`) en un outil avec menu interactif esthétique (`rich` + `questionary`), configuration persistante (`config.ini`), scan multithreadé avec payloads de contournement, rapports multi-formats (TXT/JSON/CSV/HTML) et profils de scan sauvegardés — tout en conservant un mode CLI scriptable.

**Architecture:** Le scanner monolithique actuel est découpé en un package `redirectme/` (config, payloads, scanner, report, profiles, cli) avec des interfaces claires et testables ; `main.py` devient un point d'entrée fin qui bascule entre menu interactif (aucun argument) et mode CLI classique (URL en argument positionnel).

**Tech Stack:** Python 3.9+, `requests`, `beautifulsoup4`, `rich`, `questionary`, `pytest` + `requests-mock` (tests).

**Spec:** `docs/superpowers/specs/2026-09-18-interactive-cli-design.md`

## Global Constraints

- Dépendances ajoutées : `rich>=13.7.0`, `questionary>=2.0.1` (en plus de `requests`, `beautifulsoup4` déjà présents).
- `config.ini`, `profiles/`, `reports/` sont générés localement et ignorés par git ; seul `config.ini.example` est versionné.
- Noms de profils : uniquement `[A-Za-z0-9_-]` (rejet sinon).
- Rapport HTML : template auto-contenu, sans dépendance Jinja2.
- Confirmation d'autorisation explicite obligatoire avant tout scan (menu interactif et mode CLI), sauf si `--yes` est passé en mode CLI.
- Tous les tests s'exécutent avec `python -m pytest tests/ -v` depuis la racine du repo.
- Pas de packaging pip/console-script pour l'instant : le point d'entrée reste `python main.py`.

---

### Task 1: Scaffolding du package `redirectme`

**Files:**
- Create: `redirectme/__init__.py`
- Modify: `requirements.txt`
- Create: `requirements-dev.txt`
- Modify: `.gitignore`

**Interfaces:**
- Consumes: rien (première tâche).
- Produces: le package importable `redirectme` (utilisé par toutes les tâches suivantes via `import redirectme...`).

- [ ] **Step 1: Créer le package `redirectme`**

Créer `redirectme/__init__.py` :

```python
"""RedirectMe - scanner de redirections ouvertes (open redirect)."""

__version__ = "0.2.0"
```

- [ ] **Step 2: Mettre à jour `requirements.txt`**

Contenu complet :

```
requests>=2.31.0
beautifulsoup4>=4.12.0
rich>=13.7.0
questionary>=2.0.1
```

- [ ] **Step 3: Créer `requirements-dev.txt`**

```
-r requirements.txt
pytest>=8.0.0
requests-mock>=1.12.0
```

- [ ] **Step 4: Mettre à jour `.gitignore`**

Ajouter à la fin du fichier existant :

```
config.ini
profiles/
reports/
.pytest_cache/
```

- [ ] **Step 5: Installer les dépendances et vérifier l'import**

Run: `pip install -r requirements-dev.txt && python -c "import redirectme; print(redirectme.__version__)"`
Expected: affiche `0.2.0` sans erreur.

- [ ] **Step 6: Commit**

```bash
git add redirectme/__init__.py requirements.txt requirements-dev.txt .gitignore
git commit -m "chore: scaffold redirectme package and dev dependencies"
```

---

### Task 2: Module de configuration (`redirectme/config.py`)

**Files:**
- Create: `redirectme/config.py`
- Create: `config.ini.example`
- Test: `tests/test_config.py`

**Interfaces:**
- Consumes: rien.
- Produces:
  - `AppConfig` (dataclass) avec les champs : `external_url: str`, `max_pages: int`, `timeout: int`, `min_delay: float`, `max_delay: float`, `max_workers: int`, `use_bypass_payloads: bool`, `respect_robots: bool`, `report_format: str`, `report_output_dir: str`.
  - `ConfigError(ValueError)`.
  - `load_config(path: str = "config.ini") -> AppConfig`.
  - `save_config(config: AppConfig, path: str = "config.ini") -> None`.
  - `VALID_REPORT_FORMATS: set[str]` = `{"txt", "json", "csv", "html"}`.

- [ ] **Step 1: Écrire les tests (échouants)**

Créer `tests/test_config.py` :

```python
import pytest

from redirectme.config import AppConfig, ConfigError, load_config, save_config


def test_load_config_creates_default_file(tmp_path):
    config_path = tmp_path / "config.ini"
    config = load_config(str(config_path))
    assert config == AppConfig()
    assert config_path.exists()


def test_save_and_load_round_trip(tmp_path):
    config_path = tmp_path / "config.ini"
    custom = AppConfig(
        external_url="https://attacker.test",
        max_pages=42,
        max_workers=3,
        report_format="json",
    )
    save_config(custom, str(config_path))
    loaded = load_config(str(config_path))
    assert loaded == custom


def test_load_config_rejects_invalid_int(tmp_path):
    config_path = tmp_path / "config.ini"
    config_path.write_text(
        "[general]\nexternal_url = https://evil.example.com\nmax_pages = abc\n"
        "timeout = 5\nmin_delay = 2.0\nmax_delay = 5.0\nmax_workers = 5\n"
        "[scan]\nuse_bypass_payloads = true\nrespect_robots = false\n"
        "[report]\ndefault_format = html\noutput_dir = reports\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError):
        load_config(str(config_path))


def test_load_config_rejects_invalid_report_format(tmp_path):
    config_path = tmp_path / "config.ini"
    config_path.write_text(
        "[general]\nexternal_url = https://evil.example.com\nmax_pages = 10\n"
        "timeout = 5\nmin_delay = 2.0\nmax_delay = 5.0\nmax_workers = 5\n"
        "[scan]\nuse_bypass_payloads = true\nrespect_robots = false\n"
        "[report]\ndefault_format = pdf\noutput_dir = reports\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError):
        load_config(str(config_path))
```

- [ ] **Step 2: Vérifier l'échec**

Run: `python -m pytest tests/test_config.py -v`
Expected: FAIL avec `ModuleNotFoundError: No module named 'redirectme.config'`

- [ ] **Step 3: Implémenter `redirectme/config.py`**

```python
"""Chargement et sauvegarde de la configuration RedirectMe (config.ini)."""
from __future__ import annotations

import configparser
from dataclasses import dataclass
from pathlib import Path

VALID_REPORT_FORMATS = {"txt", "json", "csv", "html"}


class ConfigError(ValueError):
    """Levée quand config.ini contient une valeur invalide."""


@dataclass
class AppConfig:
    external_url: str = "https://evil.example.com"
    max_pages: int = 100
    timeout: int = 5
    min_delay: float = 2.0
    max_delay: float = 5.0
    max_workers: int = 5
    use_bypass_payloads: bool = True
    respect_robots: bool = False
    report_format: str = "html"
    report_output_dir: str = "reports"


def _to_parser(config: AppConfig) -> configparser.ConfigParser:
    parser = configparser.ConfigParser()
    parser["general"] = {
        "external_url": config.external_url,
        "max_pages": str(config.max_pages),
        "timeout": str(config.timeout),
        "min_delay": str(config.min_delay),
        "max_delay": str(config.max_delay),
        "max_workers": str(config.max_workers),
    }
    parser["scan"] = {
        "use_bypass_payloads": str(config.use_bypass_payloads).lower(),
        "respect_robots": str(config.respect_robots).lower(),
    }
    parser["report"] = {
        "default_format": config.report_format,
        "output_dir": config.report_output_dir,
    }
    return parser


def save_config(config: AppConfig, path: str = "config.ini") -> None:
    parser = _to_parser(config)
    with open(path, "w", encoding="utf-8") as f:
        parser.write(f)


def load_config(path: str = "config.ini") -> AppConfig:
    config_path = Path(path)
    if not config_path.exists():
        default = AppConfig()
        save_config(default, path)
        return default

    parser = configparser.ConfigParser()
    parser.read(config_path, encoding="utf-8")

    try:
        general = parser["general"]
        scan = parser["scan"]
        report = parser["report"]
        config = AppConfig(
            external_url=general.get("external_url", AppConfig.external_url),
            max_pages=general.getint("max_pages"),
            timeout=general.getint("timeout"),
            min_delay=general.getfloat("min_delay"),
            max_delay=general.getfloat("max_delay"),
            max_workers=general.getint("max_workers"),
            use_bypass_payloads=scan.getboolean("use_bypass_payloads"),
            respect_robots=scan.getboolean("respect_robots"),
            report_format=report.get("default_format", AppConfig.report_format),
            report_output_dir=report.get("output_dir", AppConfig.report_output_dir),
        )
    except (KeyError, ValueError) as exc:
        raise ConfigError(f"config.ini invalide ({path}) : {exc}") from exc

    if config.report_format not in VALID_REPORT_FORMATS:
        raise ConfigError(
            f"Format de rapport invalide dans config.ini : {config.report_format!r} "
            f"(attendu : {sorted(VALID_REPORT_FORMATS)})"
        )

    return config
```

- [ ] **Step 4: Créer `config.ini.example`**

```ini
[general]
external_url = https://evil.example.com
max_pages = 100
timeout = 5
min_delay = 2.0
max_delay = 5.0
max_workers = 5

[scan]
use_bypass_payloads = true
respect_robots = false

[report]
default_format = html
output_dir = reports
```

- [ ] **Step 5: Vérifier que les tests passent**

Run: `python -m pytest tests/test_config.py -v`
Expected: PASS (4 tests)

- [ ] **Step 6: Commit**

```bash
git add redirectme/config.py config.ini.example tests/test_config.py
git commit -m "feat: add config.ini loading/saving with validation"
```

---

### Task 3: Module de payloads (`redirectme/payloads.py`)

**Files:**
- Create: `redirectme/payloads.py`
- Test: `tests/test_payloads.py`

**Interfaces:**
- Consumes: rien.
- Produces:
  - `DEFAULT_REDIRECT_PARAMS: list[str]` (paramètres de redirection connus, sans doublon).
  - `build_payloads(param: str, target_host: str, external_url: str, use_bypass: bool = True) -> list[str]`.

- [ ] **Step 1: Écrire les tests (échouants)**

Créer `tests/test_payloads.py` :

```python
from redirectme.payloads import DEFAULT_REDIRECT_PARAMS, build_payloads


def test_build_payloads_without_bypass_returns_only_raw_url():
    values = build_payloads("url", "example.com", "https://evil.example.com", use_bypass=False)
    assert values == ["https://evil.example.com"]


def test_build_payloads_with_bypass_includes_known_variants():
    values = build_payloads("url", "example.com", "https://evil.example.com", use_bypass=True)
    assert values == [
        "https://evil.example.com",
        "//evil.example.com",
        "/\\evil.example.com",
        "https:https://evil.example.com",
        "example.com@evil.example.com",
        "%2F%2Fevil.example.com",
    ]


def test_default_redirect_params_has_no_duplicates():
    assert len(DEFAULT_REDIRECT_PARAMS) == len(set(DEFAULT_REDIRECT_PARAMS))
```

- [ ] **Step 2: Vérifier l'échec**

Run: `python -m pytest tests/test_payloads.py -v`
Expected: FAIL avec `ModuleNotFoundError: No module named 'redirectme.payloads'`

- [ ] **Step 3: Implémenter `redirectme/payloads.py`**

```python
"""Paramètres de redirection connus et payloads de contournement."""
from __future__ import annotations

from urllib.parse import urlsplit

DEFAULT_REDIRECT_PARAMS = [
    "url", "redirect", "next", "return", "to", "continue", "redirect_uri",
    "target", "destination", "goto", "next_url", "post_login_redirect",
    "continue_url", "after_login", "forward_to", "landing", "next_page",
    "path", "jump", "ref", "redir", "callback", "referred_by", "from", "link",
]


def build_payloads(
    param: str, target_host: str, external_url: str, use_bypass: bool = True
) -> list[str]:
    """Retourne les valeurs à tester pour `param` afin de détecter une redirection ouverte."""
    external_host = urlsplit(external_url).netloc or external_url
    values = [external_url]
    if use_bypass:
        values.extend(
            [
                f"//{external_host}",
                f"/\\{external_host}",
                f"https:{external_url}",
                f"{target_host}@{external_host}",
                f"%2F%2F{external_host}",
            ]
        )
    return values
```

- [ ] **Step 4: Vérifier que les tests passent**

Run: `python -m pytest tests/test_payloads.py -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add redirectme/payloads.py tests/test_payloads.py
git commit -m "feat: add redirect params and bypass payload generation"
```

---

### Task 4: Module de rapports (`redirectme/report.py`)

**Files:**
- Create: `redirectme/report.py`
- Test: `tests/test_report.py`

**Interfaces:**
- Consumes: rien (types autonomes).
- Produces:
  - `Vulnerability` (dataclass) : `type: str`, `url: str`, `detail: str`.
  - `ScanResult` (dataclass) : `target: str`, `started_at: datetime`, `duration_s: float`, `pages_scanned: int`, `vulnerabilities: list[Vulnerability]`.
  - `UnsupportedFormatError(ValueError)`.
  - `generate_report(result: ScanResult, fmt: str, output_dir: str = "reports") -> Path`.
  - Utilisés par `redirectme/scanner.py` (Task 6) et `redirectme/cli.py` (Task 7).

- [ ] **Step 1: Écrire les tests (échouants)**

Créer `tests/test_report.py` :

```python
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
```

- [ ] **Step 2: Vérifier l'échec**

Run: `python -m pytest tests/test_report.py -v`
Expected: FAIL avec `ModuleNotFoundError: No module named 'redirectme.report'`

- [ ] **Step 3: Implémenter `redirectme/report.py`**

```python
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
```

- [ ] **Step 4: Vérifier que les tests passent**

Run: `python -m pytest tests/test_report.py -v`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add redirectme/report.py tests/test_report.py
git commit -m "feat: add TXT/JSON/CSV/HTML report generation"
```

---

### Task 5: Module de profils (`redirectme/profiles.py`)

**Files:**
- Create: `redirectme/profiles.py`
- Test: `tests/test_profiles.py`

**Interfaces:**
- Consumes: `redirectme.config.AppConfig` (Task 2).
- Produces:
  - `InvalidProfileNameError(ValueError)`.
  - `ProfileNotFoundError(FileNotFoundError)`.
  - `save_profile(name: str, config: AppConfig, profiles_dir: str = "profiles") -> Path`.
  - `load_profile(name: str, profiles_dir: str = "profiles") -> AppConfig`.
  - `list_profiles(profiles_dir: str = "profiles") -> list[str]`.
  - Utilisés par `redirectme/cli.py` (Task 7).

- [ ] **Step 1: Écrire les tests (échouants)**

Créer `tests/test_profiles.py` :

```python
import pytest

from redirectme.config import AppConfig
from redirectme.profiles import (
    InvalidProfileNameError,
    ProfileNotFoundError,
    list_profiles,
    load_profile,
    save_profile,
)


def test_save_and_load_profile_round_trip(tmp_path):
    profiles_dir = tmp_path / "profiles"
    config = AppConfig(external_url="https://attacker.test", max_pages=25)
    save_profile("rapide", config, str(profiles_dir))
    loaded = load_profile("rapide", str(profiles_dir))
    assert loaded == config


def test_list_profiles_returns_sorted_names(tmp_path):
    profiles_dir = tmp_path / "profiles"
    save_profile("b-profile", AppConfig(), str(profiles_dir))
    save_profile("a-profile", AppConfig(), str(profiles_dir))
    assert list_profiles(str(profiles_dir)) == ["a-profile", "b-profile"]


def test_list_profiles_on_missing_dir_returns_empty(tmp_path):
    assert list_profiles(str(tmp_path / "missing")) == []


def test_invalid_profile_name_rejected(tmp_path):
    with pytest.raises(InvalidProfileNameError):
        save_profile("../evil", AppConfig(), str(tmp_path / "profiles"))


def test_load_missing_profile_raises(tmp_path):
    with pytest.raises(ProfileNotFoundError):
        load_profile("ghost", str(tmp_path / "profiles"))
```

- [ ] **Step 2: Vérifier l'échec**

Run: `python -m pytest tests/test_profiles.py -v`
Expected: FAIL avec `ModuleNotFoundError: No module named 'redirectme.profiles'`

- [ ] **Step 3: Implémenter `redirectme/profiles.py`**

```python
"""Sauvegarde et chargement de profils de scan nommés."""
from __future__ import annotations

import json
import re
from dataclasses import asdict
from pathlib import Path

from redirectme.config import AppConfig

PROFILE_NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")


class InvalidProfileNameError(ValueError):
    """Levée quand un nom de profil contient des caractères non autorisés."""


class ProfileNotFoundError(FileNotFoundError):
    """Levée quand le profil demandé n'existe pas."""


def _profile_path(name: str, profiles_dir: str = "profiles") -> Path:
    if not PROFILE_NAME_RE.match(name):
        raise InvalidProfileNameError(f"Nom de profil invalide : {name!r}")
    return Path(profiles_dir) / f"{name}.json"


def save_profile(name: str, config: AppConfig, profiles_dir: str = "profiles") -> Path:
    path = _profile_path(name, profiles_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(asdict(config), indent=2), encoding="utf-8")
    return path


def load_profile(name: str, profiles_dir: str = "profiles") -> AppConfig:
    path = _profile_path(name, profiles_dir)
    if not path.exists():
        raise ProfileNotFoundError(f"Profil introuvable : {name}")
    data = json.loads(path.read_text(encoding="utf-8"))
    return AppConfig(**data)


def list_profiles(profiles_dir: str = "profiles") -> list[str]:
    directory = Path(profiles_dir)
    if not directory.exists():
        return []
    return sorted(p.stem for p in directory.glob("*.json"))
```

- [ ] **Step 4: Vérifier que les tests passent**

Run: `python -m pytest tests/test_profiles.py -v`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add redirectme/profiles.py tests/test_profiles.py
git commit -m "feat: add named scan profile save/load"
```

---

### Task 6: Moteur de scan multithread (`redirectme/scanner.py`)

**Files:**
- Create: `redirectme/scanner.py`
- Test: `tests/test_scanner.py`

**Interfaces:**
- Consumes:
  - `redirectme.config.AppConfig` (Task 2).
  - `redirectme.payloads.DEFAULT_REDIRECT_PARAMS`, `build_payloads` (Task 3).
  - `redirectme.report.ScanResult`, `Vulnerability` (Task 4).
- Produces:
  - `same_site(url: str, target_netloc: str) -> bool`.
  - `RedirectScanner(target: str, config: AppConfig, on_progress: Callable[[str, dict], None] | None = None)`.
    - `.crawl() -> ScanResult`
    - `.result() -> ScanResult`
    - `.request_with_retry(url: str, retries: int | None = None) -> requests.Response | None`
    - `.visited_urls: set[str]`, `.vulnerabilities: list[Vulnerability]`
  - Événements `on_progress` : `("page_scanned", {"url": str, "count": int})`,
    `("link_tested", {"url": str})`, `("vulnerability_found", {"vulnerability": Vulnerability})`.
  - Utilisé par `redirectme/cli.py` (Task 7) et `main.py` (Task 8).

- [ ] **Step 1: Écrire les tests (échouants)**

Créer `tests/test_scanner.py` :

```python
from requests_mock import ANY as ANY_URL

from redirectme.config import AppConfig
from redirectme.scanner import RedirectScanner, same_site


def make_config(**overrides):
    base = dict(
        external_url="https://evil.example.com",
        max_pages=10,
        timeout=5,
        min_delay=0,
        max_delay=0,
        max_workers=1,
        use_bypass_payloads=False,
        respect_robots=False,
        report_format="txt",
        report_output_dir="reports",
    )
    base.update(overrides)
    return AppConfig(**base)


def test_same_site_compares_exact_netloc():
    assert same_site("https://example.com/path", "example.com")
    assert not same_site("https://evil.example.com.attacker.test/path", "example.com")


def test_crawl_detects_vulnerable_param(requests_mock):
    requests_mock.get(
        "http://example.com",
        text='<html><body><a href="/page1">link</a></body></html>',
        headers={"Content-Type": "text/html"},
    )
    requests_mock.get(
        "http://example.com/page1",
        text="<html></html>",
        headers={"Content-Type": "text/html"},
    )
    requests_mock.get(ANY_URL, status_code=200, headers={"Content-Type": "text/html"})
    requests_mock.get(
        "http://example.com/page1?url=https%3A%2F%2Fevil.example.com",
        status_code=302,
        headers={"Location": "https://evil.example.com"},
    )

    config = make_config(max_workers=2)
    scanner = RedirectScanner("http://example.com", config)
    result = scanner.crawl()

    assert result.pages_scanned == 2
    assert len(result.vulnerabilities) == 1
    assert result.vulnerabilities[0].type == "param"
    assert "url=" in result.vulnerabilities[0].url


def test_request_with_retry_handles_429(requests_mock, monkeypatch):
    monkeypatch.setattr("redirectme.scanner.time.sleep", lambda seconds: None)
    url = "http://example.com/limited"
    requests_mock.get(
        url,
        [
            {"status_code": 429, "headers": {"Retry-After": "1"}},
            {"status_code": 200, "text": "ok", "headers": {"Content-Type": "text/html"}},
        ],
    )
    config = make_config()
    scanner = RedirectScanner("http://example.com", config)
    response = scanner.request_with_retry(url)
    assert response.status_code == 200


def test_respects_robots_txt(requests_mock, monkeypatch):
    monkeypatch.setattr("redirectme.scanner.time.sleep", lambda seconds: None)
    requests_mock.get(
        "http://example.com/robots.txt",
        text="User-agent: *\nDisallow: /private\n",
        headers={"Content-Type": "text/plain"},
    )
    requests_mock.get(
        "http://example.com",
        text='<html><body><a href="/private">x</a><a href="/public">y</a></body></html>',
        headers={"Content-Type": "text/html"},
    )
    requests_mock.get(
        "http://example.com/public",
        text="<html></html>",
        headers={"Content-Type": "text/html"},
    )
    requests_mock.get(ANY_URL, status_code=200, headers={"Content-Type": "text/html"})

    config = make_config(respect_robots=True, max_pages=10)
    scanner = RedirectScanner("http://example.com", config)
    scanner.crawl()

    requested_urls = {req.url for req in requests_mock.request_history}
    assert not any(url.startswith("http://example.com/private") for url in requested_urls)
    assert "http://example.com/public" in requested_urls
```

- [ ] **Step 2: Vérifier l'échec**

Run: `python -m pytest tests/test_scanner.py -v`
Expected: FAIL avec `ModuleNotFoundError: No module named 'redirectme.scanner'`

- [ ] **Step 3: Implémenter `redirectme/scanner.py`**

```python
"""Moteur de scan RedirectMe : crawl, détection de redirections ouvertes."""
from __future__ import annotations

import logging
import random
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Callable, Optional
from urllib.parse import urljoin, urlencode, urlparse
from urllib.robotparser import RobotFileParser

import requests
from bs4 import BeautifulSoup

from redirectme.config import AppConfig
from redirectme.payloads import DEFAULT_REDIRECT_PARAMS, build_payloads
from redirectme.report import ScanResult, Vulnerability

DEFAULT_MAX_RETRIES = 5

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Firefox/89.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Edge/91.0.864.59",
]

JS_REDIRECT_REGEX = re.compile(
    r"(?:window\.location\.href|location\.replace)\s*\(\s*['\"]([^'\"]+)['\"]"
)

logger = logging.getLogger("redirectme")

ProgressCallback = Callable[[str, dict], None]


def same_site(url: str, target_netloc: str) -> bool:
    """Vérifie que `url` appartient exactement au domaine ciblé (comparaison du netloc)."""
    return urlparse(url).netloc == target_netloc


class RedirectScanner:
    """Explore un site et détecte les redirections ouvertes."""

    def __init__(
        self, target: str, config: AppConfig, on_progress: Optional[ProgressCallback] = None
    ):
        self.target = target.rstrip("/")
        self.config = config
        self.target_netloc = urlparse(self.target).netloc
        self.on_progress = on_progress or (lambda event, data: None)
        self.visited_urls: set[str] = set()
        self.visited_lock = threading.Lock()
        self.vulnerabilities: list[Vulnerability] = []
        self.vuln_lock = threading.Lock()
        self.session = requests.Session()
        self._start_time: datetime | None = None
        self._start_perf: float | None = None
        self._robot_parser: RobotFileParser | None = None
        if self.config.respect_robots:
            self._robot_parser = self._load_robots_txt()

    def _load_robots_txt(self) -> RobotFileParser:
        parser = RobotFileParser()
        robots_url = urljoin(self.target + "/", "/robots.txt")
        parser.set_url(robots_url)
        try:
            response = self.session.get(robots_url, timeout=self.config.timeout)
            parser.parse(response.text.splitlines() if response.status_code == 200 else [])
        except requests.exceptions.RequestException:
            parser.parse([])
        return parser

    def _is_allowed(self, url: str) -> bool:
        if self._robot_parser is None:
            return True
        return self._robot_parser.can_fetch("*", url)

    def request_with_retry(
        self, url: str, retries: int | None = None
    ) -> requests.Response | None:
        """Effectue une requête GET avec gestion des erreurs 429 et backoff exponentiel."""
        retries = DEFAULT_MAX_RETRIES if retries is None else retries
        backoff_factor = 2
        for attempt in range(retries):
            try:
                response = self.session.get(
                    url,
                    timeout=self.config.timeout,
                    headers={"User-Agent": random.choice(USER_AGENTS)},
                    allow_redirects=False,
                )
            except requests.exceptions.RequestException as exc:
                logger.error("Erreur de requête sur %s : %s", url, exc)
                return None

            if response.status_code == 429:
                retry_after = response.headers.get("Retry-After")
                wait_time = int(retry_after) if retry_after else backoff_factor * (2**attempt)
                logger.warning(
                    "429 reçu sur %s, attente de %ss avant nouvel essai...", url, wait_time
                )
                time.sleep(wait_time)
                continue
            return response
        return None

    def get_all_links(self, url: str) -> list[str]:
        """Récupère tous les liens (href) présents sur une page."""
        response = self.request_with_retry(url)
        if response is None or "text/html" not in response.headers.get("Content-Type", ""):
            return []
        soup = BeautifulSoup(response.text, "html.parser")
        return [a["href"] for a in soup.find_all("a", href=True)]

    def get_js_redirects(self, url: str) -> list[str]:
        """Recherche les redirections déclenchées en JavaScript sur une page."""
        response = self.request_with_retry(url)
        if response is None:
            return []
        return JS_REDIRECT_REGEX.findall(response.text)

    def is_open_redirect(self, test_url: str) -> bool:
        """Vérifie si `test_url` redirige (3xx) vers l'URL externe de test."""
        response = self.request_with_retry(test_url, retries=3)
        if response is None or not (300 <= response.status_code < 400):
            return False
        location = response.headers.get("Location", "")
        return self.config.external_url in location

    def _test_link(self, full_link: str) -> None:
        if not self._is_allowed(full_link):
            return
        for param in DEFAULT_REDIRECT_PARAMS:
            for value in build_payloads(
                param, self.target_netloc, self.config.external_url, self.config.use_bypass_payloads
            ):
                separator = "&" if "?" in full_link else "?"
                test_url = f"{full_link}{separator}{urlencode({param: value})}"
                self.on_progress("link_tested", {"url": test_url})
                if self.is_open_redirect(test_url):
                    self._report_vulnerability("param", test_url, f"{param}={value}")

        for js_url in self.get_js_redirects(full_link):
            absolute_js_url = urljoin(full_link, js_url)
            if same_site(absolute_js_url, self.target_netloc) and self.is_open_redirect(
                absolute_js_url
            ):
                self._report_vulnerability(
                    "javascript", absolute_js_url, f"depuis {full_link}"
                )

    def scan_page_for_redirects(self, page_url: str) -> list[str]:
        """Teste les liens d'une page (en parallèle) et retourne tous les liens absolus trouvés."""
        links = [urljoin(page_url, href) for href in self.get_all_links(page_url)]
        same_site_links = [link for link in links if same_site(link, self.target_netloc)]
        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            list(executor.map(self._test_link, same_site_links))
        return links

    def scan_form_for_redirects(self, page_url: str) -> None:
        """Soumet les formulaires d'une page en injectant l'URL externe dans les champs de redirection."""
        if not self._is_allowed(page_url):
            return
        response = self.request_with_retry(page_url)
        if response is None:
            return
        soup = BeautifulSoup(response.text, "html.parser")

        for form in soup.find_all("form"):
            action = form.get("action")
            if not action:
                continue
            full_action = urljoin(page_url, action)
            if not same_site(full_action, self.target_netloc):
                continue

            data = {
                tag.get("name"): tag.get("value", "")
                for tag in form.find_all("input")
                if tag.get("name")
            }
            for param in DEFAULT_REDIRECT_PARAMS:
                if param in data:
                    data[param] = self.config.external_url

            response = self.request_with_retry(full_action, retries=3)
            if response is not None and self.is_open_redirect(response.url):
                self._report_vulnerability("form", full_action, "soumission de formulaire")

    def _report_vulnerability(self, vuln_type: str, url: str, detail: str) -> None:
        with self.vuln_lock:
            vuln = Vulnerability(type=vuln_type, url=url, detail=detail)
            self.vulnerabilities.append(vuln)
        logger.warning("[VULNÉRABLE] %s (%s)", url, detail)
        self.on_progress("vulnerability_found", {"vulnerability": vuln})

    def crawl(self) -> ScanResult:
        """Explore le site en largeur, jusqu'à `max_pages`, et scanne chaque page visitée."""
        self._start_time = datetime.now()
        self._start_perf = time.perf_counter()
        urls_to_visit = [self.target]

        while urls_to_visit and len(self.visited_urls) < self.config.max_pages:
            current_url = urls_to_visit.pop(0)
            with self.visited_lock:
                if current_url in self.visited_urls:
                    continue
                self.visited_urls.add(current_url)

            if not self._is_allowed(current_url):
                logger.info("Ignoré (robots.txt) : %s", current_url)
                continue

            self.on_progress(
                "page_scanned", {"url": current_url, "count": len(self.visited_urls)}
            )

            links = self.scan_page_for_redirects(current_url)
            self.scan_form_for_redirects(current_url)

            for link in links:
                if same_site(link, self.target_netloc) and link not in self.visited_urls:
                    urls_to_visit.append(link)

            time.sleep(random.uniform(self.config.min_delay, self.config.max_delay))

        return self.result()

    def result(self) -> ScanResult:
        """Construit un `ScanResult` à partir de l'état courant (scan terminé ou interrompu)."""
        duration = (
            time.perf_counter() - self._start_perf if self._start_perf is not None else 0.0
        )
        return ScanResult(
            target=self.target,
            started_at=self._start_time or datetime.now(),
            duration_s=duration,
            pages_scanned=len(self.visited_urls),
            vulnerabilities=list(self.vulnerabilities),
        )
```

- [ ] **Step 4: Vérifier que les tests passent**

Run: `python -m pytest tests/test_scanner.py -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add redirectme/scanner.py tests/test_scanner.py
git commit -m "feat: multithreaded scan engine with bypass payloads and robots.txt support"
```

---

### Task 7: Menu interactif (`redirectme/cli.py`)

**Files:**
- Create: `redirectme/cli.py`

**Interfaces:**
- Consumes:
  - `redirectme.config.AppConfig`, `ConfigError`, `load_config`, `save_config` (Task 2).
  - `redirectme.profiles.list_profiles`, `load_profile`, `save_profile` (Task 5).
  - `redirectme.report.ScanResult`, `generate_report` (Task 4).
  - `redirectme.scanner.RedirectScanner` (Task 6).
- Produces:
  - `run_interactive_menu(config_path: str = "config.ini") -> None`.
  - Utilisé par `main.py` (Task 8).

Pas de tests automatisés pour ce module (interaction terminal via `questionary`) — vérification manuelle au Step 3.

- [ ] **Step 1: Implémenter `redirectme/cli.py`**

```python
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
```

- [ ] **Step 2: Vérifier que le module s'importe sans erreur**

Run: `python -c "import redirectme.cli; print('ok')"`
Expected: affiche `ok` sans erreur.

- [ ] **Step 3: Vérification manuelle du menu**

Run: `python -c "from redirectme.cli import run_interactive_menu; run_interactive_menu()"` dans un terminal interactif (PowerShell ou un vrai TTY — pas via un pipe non interactif).
Expected: la bannière et le menu `questionary` s'affichent, navigation possible aux flèches, "Quitter" ferme proprement sans erreur.

- [ ] **Step 4: Commit**

```bash
git add redirectme/cli.py
git commit -m "feat: add interactive rich/questionary menu"
```

---

### Task 8: Point d'entrée `main.py`

**Files:**
- Modify: `main.py` (remplacement complet du contenu actuel)
- Test: `tests/test_main.py`

**Interfaces:**
- Consumes: `redirectme.cli.run_interactive_menu` (Task 7), `redirectme.config.load_config` (Task 2), `redirectme.report.generate_report` (Task 4), `redirectme.scanner.RedirectScanner` (Task 6).
- Produces: `parse_args(argv=None) -> argparse.Namespace`, `run_cli(args) -> int`, `main(argv=None) -> int`.

- [ ] **Step 1: Écrire les tests (échouants)**

Créer `tests/test_main.py` :

```python
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
```

- [ ] **Step 2: Vérifier l'échec**

Run: `python -m pytest tests/test_main.py -v`
Expected: FAIL (le `main.py` actuel n'expose pas `parse_args`/`run_cli` avec cette signature, ou lève une erreur d'import liée à `redirectme.cli` absent du chemin d'exécution précédent)

- [ ] **Step 3: Remplacer `main.py`**

```python
#!/usr/bin/env python3
"""RedirectMe - scanner de redirections ouvertes (open redirect)."""
from __future__ import annotations

import argparse
import logging
import sys

from redirectme.cli import run_interactive_menu
from redirectme.config import load_config
from redirectme.report import generate_report
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
        choices=["txt", "json", "csv", "html"],
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

    print(f"Scan de {args.target} à la recherche de redirections ouvertes...\n")
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
```

- [ ] **Step 4: Vérifier que les tests passent**

Run: `python -m pytest tests/test_main.py -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Lancer la suite complète**

Run: `python -m pytest tests/ -v`
Expected: PASS (tous les tests des tâches 2 à 8, aucun échec)

- [ ] **Step 6: Commit**

```bash
git add main.py tests/test_main.py
git commit -m "feat: rewire main.py as thin entry point (menu or scriptable CLI)"
```

---

### Task 9: Documentation et nettoyage final

**Files:**
- Modify: `README.md` (remplacement complet)
- Modify: `docs/superpowers/specs/2026-09-18-interactive-cli-design.md` (aucun changement de contenu — vérification de cohérence uniquement)

**Interfaces:**
- Consumes: rien (documentation).
- Produces: rien (dernière tâche).

- [ ] **Step 1: Remplacer `README.md`**

```markdown
# 🔀 RedirectMe

**Scanner de redirections ouvertes (open redirect) pour l'audit de sécurité web — menu interactif, payloads de contournement, rapports HTML.**

[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

RedirectMe explore un site web et teste ses liens, ses scripts JavaScript et
ses formulaires afin de détecter des **redirections ouvertes** — une faille
souvent exploitée dans des campagnes de **phishing**, où une URL en apparence
légitime redirige finalement vers un site malveillant.

> ⚠️ **Usage éthique uniquement.** N'utilisez cet outil que sur des sites que
> vous possédez ou pour lesquels vous avez une autorisation explicite (test
> d'intrusion, bug bounty, CTF). Scanner un site tiers sans accord est illégal
> dans la plupart des juridictions. Une confirmation d'autorisation est
> demandée avant chaque scan.

---

## Sommaire

- [Fonctionnalités](#fonctionnalités)
- [Installation](#installation)
- [Utilisation](#utilisation)
  - [Menu interactif](#menu-interactif)
  - [Mode scriptable (CLI)](#mode-scriptable-cli)
- [Configuration (`config.ini`)](#configuration-configini)
- [Profils de scan](#profils-de-scan)
- [Formats de rapport](#formats-de-rapport)
- [Comment ça marche](#comment-ça-marche)
- [Contribuer](#contribuer)
- [Licence](#licence)

---

## Fonctionnalités

- 🖥️ **Menu interactif** coloré (`rich` + `questionary`) : lancement de scan,
  gestion des profils, édition de la configuration, consultation du dernier rapport.
- 🕷️ **Crawl multithreadé**, limité au même domaine et à un nombre de pages configurable.
- 🔗 **Paramètres de redirection** classiques (`url`, `redirect`, `next`, `goto`...)
  testés sur chaque lien.
- 🧪 **Payloads de contournement** (protocol-relative `//`, trick `@`, encodage, etc.)
  pour détecter des variantes que les filtres naïfs laissent passer.
- 🧩 **Détection des redirections JavaScript** (`window.location.href`, `location.replace`).
- 📝 **Scan des formulaires** en injectant l'URL de test dans les champs de redirection.
- 🤖 **Respect optionnel de `robots.txt`**.
- 🔁 **Gestion des erreurs et des 429** avec backoff exponentiel et rotation de User-Agent.
- 💾 **Rapports** en TXT, JSON, CSV ou HTML (ouvrable dans le navigateur).
- 🗂️ **Profils de scan sauvegardés** pour réutiliser des réglages nommés.
- ⚙️ **`config.ini`** auto-généré et éditable depuis le menu.

---

## Installation

Python 3.9 ou supérieur est requis.

```bash
git clone https://github.com/arditore/RedirectMe.git
cd RedirectMe
pip install -r requirements.txt
```

Pour contribuer ou lancer les tests, installez aussi les dépendances de dev :

```bash
pip install -r requirements-dev.txt
python -m pytest tests/ -v
```

---

## Utilisation

### Menu interactif

Lancez l'outil sans argument pour ouvrir le menu :

```bash
python main.py
```

```
╔══════════════════════════╗
║        RedirectMe        ║
║  Open Redirect Scanner   ║
╚══════════════════════════╝

1. Lancer un scan
2. Charger un profil de scan
3. Configuration
4. Voir le dernier rapport
5. Quitter
```

Le menu vous guide : URL cible, options du scan, confirmation d'autorisation,
barre de progression en temps réel, puis résumé coloré et génération du rapport.

### Mode scriptable (CLI)

Pour l'automatisation/CI, passez l'URL en argument :

```bash
python main.py https://example.com --yes --output-format json
```

```
usage: main.py [-h] [--no-interactive] [--yes] [--config CONFIG]
                [--external-url EXTERNAL_URL] [--max-pages MAX_PAGES]
                [--output-format {txt,json,csv,html}] [--output-dir OUTPUT_DIR]
                [-v]
                [target]

positional arguments:
  target                URL de base du site à scanner (ex : https://example.com)

options:
  -h, --help            affiche ce message d'aide
  --no-interactive      force le mode CLI (sans menu interactif)
  --yes                 confirme automatiquement l'autorisation de scan
  --config CONFIG       chemin du fichier config.ini (défaut : config.ini)
  --external-url URL    surcharge l'URL externe de test
  --max-pages N         surcharge le nombre max de pages
  --output-format FMT   surcharge le format de rapport (txt, json, csv, html)
  --output-dir DIR      surcharge le dossier de sortie des rapports
  -v, --verbose         affiche les logs détaillés
```

---

## Configuration (`config.ini`)

Généré automatiquement au premier lancement (voir `config.ini.example`) :

```ini
[general]
external_url = https://evil.example.com
max_pages = 100
timeout = 5
min_delay = 2.0
max_delay = 5.0
max_workers = 5

[scan]
use_bypass_payloads = true
respect_robots = false

[report]
default_format = html
output_dir = reports
```

Éditable directement depuis le menu ("Configuration") ou en modifiant le fichier.

---

## Profils de scan

Depuis le menu, sauvegardez vos réglages actuels sous un nom ("scan-rapide",
"scan-complet"...) et rechargez-les au prochain lancement via
"Charger un profil de scan". Les profils sont stockés dans `profiles/*.json`.

---

## Formats de rapport

- **TXT** : liste simple, une ligne par vulnérabilité.
- **JSON** : structure complète (cible, dates, stats, vulnérabilités) pour intégration avec d'autres outils.
- **CSV** : une ligne par vulnérabilité, pour tableur.
- **HTML** : rapport stylé, proposé automatiquement dans le navigateur en fin de scan interactif.

Les rapports sont écrits dans `reports/` (configurable).

---

## Comment ça marche

1. **Crawl** : le script part de l'URL cible et suit les liens internes (même nom de domaine uniquement), jusqu'à `max_pages` pages, en respectant `robots.txt` si activé.
2. **Injection multithreadée** : pour chaque lien, chaque paramètre connu est testé avec l'URL externe et, si activé, ses variantes de contournement.
3. **Vérification** : une réponse HTTP 3xx dont l'en-tête `Location` pointe vers l'URL externe est considérée comme une redirection ouverte.
4. **JavaScript & formulaires** : le même principe est appliqué aux redirections détectées dans le code JS et aux champs de formulaire.
5. **Rapport** : les résultats sont exportés dans le format choisi.

---

## Contribuer

Les contributions sont bienvenues. Ouvrez une issue ou une pull request pour
proposer une amélioration ou signaler un bug. Merci d'inclure des tests
(`python -m pytest tests/ -v`) pour toute nouvelle fonctionnalité.

## Licence

Distribué sous licence [MIT](LICENSE).
```

- [ ] **Step 2: Smoke test final**

Run: `python -m pytest tests/ -v && python main.py --help`
Expected: tous les tests passent, et l'aide `argparse` s'affiche sans erreur.

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: document interactive menu, config.ini, profiles and report formats"
```

---

## Self-Review Notes

- **Spec coverage** : structure package (Task 1), config.ini auto-généré + édition (Task 2 + 7), scan multithread (Task 6), payloads de contournement (Task 3 + 6), rapports TXT/JSON/CSV/HTML (Task 4), profils (Task 5), menu interactif (Task 7), mode CLI conservé (Task 8), garde-fou d'autorisation (Task 7 + 8), README mis à jour (Task 9) — toutes les sections du spec sont couvertes.
- **Placeholders** : aucun `TBD`/`TODO` ; chaque step contient le code complet à écrire.
- **Cohérence des types** : `AppConfig`, `ScanResult`, `Vulnerability`, `RedirectScanner`, `build_payloads`, `generate_report`, `save_profile`/`load_profile`/`list_profiles` utilisent les mêmes signatures dans toutes les tâches qui les consomment.
