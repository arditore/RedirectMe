# RedirectMe — Interface CLI interactive & fonctionnalités avancées

Date : 2026-09-18
Statut : approuvé (en attente de revue finale avant implémentation)

## Contexte

`RedirectMe` est un scanner d'open redirects en Python, actuellement un
script unique (`main.py`) piloté uniquement par `argparse`. L'utilisateur
souhaite une expérience beaucoup plus riche : un menu interactif esthétique,
une configuration persistante (`config.ini`), et plusieurs fonctionnalités de
scan avancées (multithreading, payloads de contournement, rapports
multi-formats, profils de scan sauvegardés).

## Objectifs

- Lancer l'outil sans argument doit ouvrir un **menu interactif** soigné
  (couleurs, tableaux, barre de progression) construit avec `rich` +
  `questionary`.
- Les réglages par défaut vivent dans un **`config.ini`** auto-généré,
  éditable directement depuis le menu.
- Le scan devient **multithreadé** (plus rapide) et teste des
  **payloads de contournement** (pas seulement `?param=url_externe`).
- Les résultats sont exportables en **TXT / JSON / CSV / HTML**.
- Les réglages de scan peuvent être sauvegardés/rechargés comme
  **profils nommés**.
- Le mode scriptable existant (arguments en ligne de commande, utilisable en
  CI/automatisation) est conservé.

## Hors scope

- Pas d'interface web/graphique — uniquement terminal.
- Pas de base de données — profils et rapports en fichiers plats (JSON/HTML/CSV/TXT).
- Pas de packaging PyPI/`pip install` global pour l'instant (`python main.py` reste le point d'entrée).
- Pas de scan distribué multi-machines — un seul process, un pool de threads local.

## Structure du projet

```
RedirectMe/
├── main.py                     # point d'entrée (menu interactif ou CLI directe)
├── redirectme/
│   ├── __init__.py
│   ├── cli.py                   # menu interactif (rich + questionary)
│   ├── config.py                 # lecture/écriture config.ini (configparser)
│   ├── scanner.py                 # RedirectScanner multithread (issu de l'actuel main.py)
│   ├── payloads.py                 # liste de paramètres + payloads de contournement
│   ├── report.py                    # export TXT / JSON / CSV / HTML
│   └── profiles.py                   # sauvegarde/chargement de profils de scan (JSON)
├── config.ini.example
├── profiles/                    # profils utilisateur sauvegardés (gitignored, dossier créé au besoin)
├── reports/                     # rapports générés (gitignored)
├── requirements.txt             # + rich, questionary
├── README.md
```

`config.ini`, `profiles/*.json` et `reports/*` sont générés localement et
ajoutés au `.gitignore` (seul `config.ini.example` est versionné).

## Point d'entrée (`main.py`)

- Aucun argument → lance `redirectme.cli.run_interactive_menu()`.
- Un argument positionnel (`target`) ou `--no-interactive` → comportement CLI
  actuel conservé (argparse), pour scripting/CI. Les mêmes options
  (`--max-pages`, `--output`, etc.) restent disponibles, avec les valeurs de
  `config.ini` comme défauts au lieu des valeurs codées en dur.
- `--yes` (CLI) permet de sauter la confirmation d'autorisation en mode non
  interactif.

## Menu interactif (`redirectme/cli.py`)

Écran d'accueil (bannière `rich` + couleurs) :

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

Navigation via `questionary.select` (flèches + entrée). Chaque écran peut
revenir au menu principal.

### 1. Lancer un scan
1. Prompt `questionary.text` pour l'URL cible, avec validation basique
   (schéma `http(s)://` présent).
2. Récapitulatif des options actives (issues de `config.ini` ou du profil
   chargé) affiché dans un tableau `rich.table.Table` ; proposition de les
   modifier ponctuellement (external_url, max_pages, max_workers,
   use_bypass_payloads, format de rapport) via `questionary`.
3. **Confirmation d'autorisation obligatoire** : "Confirmez-vous être
   autorisé à tester cette cible ? (o/N)" → annule le scan si refusé.
4. Lancement du scan avec `rich.progress.Progress` (colonnes : pages
   scannées/total, liens testés, vulnérabilités trouvées, temps écoulé).
5. À la fin : tableau récapitulatif coloré (vert = sûr, rouge = vulnérable),
   proposition d'ouvrir le rapport HTML généré dans le navigateur
   (`webbrowser.open`).

### 2. Charger un profil de scan
Liste les profils disponibles (`profiles/*.json`), sélection via
`questionary.select`, préremplit les options de l'écran "Lancer un scan".

### 3. Configuration
Édite les valeurs de `config.ini` section par section (formulaires
`questionary`), avec validation de type (int/float/bool/URL) avant
sauvegarde. Propose aussi "Sauvegarder les réglages actuels comme nouveau
profil".

### 4. Voir le dernier rapport
Affiche le chemin du dernier rapport généré et propose de l'ouvrir
(HTML → navigateur, autres → chemin affiché).

## Configuration (`redirectme/config.py`)

`config.ini` généré automatiquement au premier lancement s'il est absent
(valeurs ci-dessous), via `configparser` :

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

`config.py` expose :
- `load_config(path: str = "config.ini") -> AppConfig` (dataclass typée,
  crée le fichier avec les valeurs par défaut s'il n'existe pas, valide les
  types et republie des erreurs claires si une valeur est invalide).
- `save_config(config: AppConfig, path: str = "config.ini") -> None`.

`AppConfig` est la dataclass typée utilisée dans tout le reste de
l'application (remplace l'actuel `ScanConfig` en l'étendant avec
`max_workers`, `use_bypass_payloads`, `respect_robots`, `report_format`,
`report_output_dir`).

## Moteur de scan (`redirectme/scanner.py`)

Reprend `RedirectScanner` existant avec :

- **Multithreading** : `concurrent.futures.ThreadPoolExecutor` de taille
  `max_workers` pour paralléliser les tests de payloads sur les liens d'une
  page. Le crawl reste en BFS ; `visited_urls` est protégé par un
  `threading.Lock`. Chaque thread respecte son propre délai aléatoire
  (`min_delay`/`max_delay`) avant requête — la parallélisation augmente donc
  le débit total de façon proportionnelle à `max_workers`, ce qui est
  documenté comme compromis vitesse/discrétion (valeur par défaut modérée :
  5).
- **Callback de progression** : le scanner accepte un callback optionnel
  appelé à chaque page/lien/vulnérabilité pour alimenter la barre `rich`
  (découplage propre entre logique de scan et UI).
- Comportement CLI historique (séquentiel si `max_workers = 1`) reste
  possible.

## Payloads de contournement (`redirectme/payloads.py`)

En plus du test simple `?param=external_url`, génère (si
`use_bypass_payloads = true`) des variantes par paramètre :

- `external_url` brut
- `//<host_externe>` (protocol-relative)
- `/\<host_externe>`
- `https:<url_externe>` (slashes manquants)
- `<host_cible>@<host_externe>` (trick userinfo)
- `%2F%2F<host_externe>` (encodage de `//`)

Fonction pure `build_payloads(param: str, target_host: str, external_url: str) -> list[str]`,
testable indépendamment du scanner.

## Rapports (`redirectme/report.py`)

`generate_report(result: ScanResult, fmt: str, output_dir: str) -> Path` :
- **TXT** : comportement actuel (une ligne par vulnérabilité).
- **JSON** : `{ "target": ..., "started_at": ..., "duration_s": ...,
  "pages_scanned": N, "vulnerabilities": [ {type, url, detail}, ... ] }`.
- **CSV** : une ligne par vulnérabilité (colonnes : type, url, détail).
- **HTML** : template simple auto-contenu (pas de dépendance Jinja2),
  tableau stylé + résumé, ouvrable directement dans un navigateur.

`ScanResult` (dataclass) centralise les métadonnées d'un scan (cible, dates,
stats, liste de vulnérabilités) — produit par `scanner.py`, consommé par
`report.py` et par l'écran "Voir le dernier rapport".

## Profils (`redirectme/profiles.py`)

- `save_profile(name: str, config: AppConfig) -> None` → écrit
  `profiles/<name>.json`.
- `load_profile(name: str) -> AppConfig`.
- `list_profiles() -> list[str]`.
- Noms de profils validés (slug alphanumérique + `-`/`_`) pour éviter tout
  souci de chemin de fichier.

## Garde-fou éthique

Le mode interactif exige une confirmation explicite d'autorisation avant
tout scan. Le mode CLI/scriptable respecte la même règle sauf si `--yes` est
passé explicitement. Le README rappelle l'usage autorisé uniquement (déjà en
place, conservé et mis à jour avec les nouvelles fonctionnalités).

## Dépendances ajoutées

```
rich>=13.7.0
questionary>=2.0.1
```
(`requests` et `beautifulsoup4` inchangés.)

## Tests

- `payloads.py::build_payloads` : tests unitaires purs (pas de réseau).
- `config.py::load_config`/`save_config` : tests sur fichiers temporaires
  (génération par défaut, round-trip, valeurs invalides).
- `profiles.py` : tests sur dossier temporaire (save/load/list, noms
  invalides rejetés).
- `report.py::generate_report` : tests par format sur un `ScanResult`
  factice (vérifie la structure du fichier généré).
- `scanner.py` : tests avec `requests_mock` ou `responses` pour simuler des
  réponses HTTP (redirections vulnérables/sûres, 429, timeout), y compris en
  mode multithreadé (vérifier absence de doublons dans `visited_urls`).
- Le menu interactif (`cli.py`) n'est pas testé unitairement (I/O terminal) ;
  revue manuelle après implémentation.

## Migration

L'actuel `main.py` (scanner monolithique livré précédemment) est déplacé/
réparti dans `redirectme/scanner.py` et `redirectme/payloads.py` ; `main.py`
devient un point d'entrée fin. Le README est mis à jour pour documenter le
menu interactif, `config.ini`, les profils et les formats de rapport.
