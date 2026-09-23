# 🔀 RedirectMe 🐧

**Scanner de redirections ouvertes (open redirect) pour l'audit de sécurité web — menu interactif, payloads de contournement, rapports HTML.**

*noot noot — le pingouin qui traque les redirections louches.*

[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

```
      .--.
     |o_o |
     |:_/ |
    //   \ \
   (|     | )
  /'\_   _/`\
  \___)=(___/
        noot noot 🐧
```

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
      .--.
     |o_o |
     |:_/ |
    //   \ \
   (|     | )
  /'\_   _/`\
  \___)=(___/
        noot noot 🐧
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

---

🐧 *noot noot*
