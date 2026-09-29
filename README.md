# 🔀 RedirectMe 🐧

**Open redirect scanner for web security audits — interactive menu, bypass payloads, HTML reports.**

*noot noot — the penguin that hunts down shady redirects.*

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

RedirectMe crawls a website and tests its links, JavaScript and forms to
detect **open redirects** — a flaw often exploited in **phishing**
campaigns, where a seemingly legitimate URL ultimately redirects to a
malicious site.

> ⚠️ **Ethical use only.** Only use this tool on sites you own or have
> explicit authorization to test (penetration testing, bug bounty, CTF).
> Scanning a third-party site without consent is illegal in most
> jurisdictions. An authorization confirmation is requested before every
> scan.

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
  - [Interactive menu](#interactive-menu)
  - [Scriptable mode (CLI)](#scriptable-mode-cli)
- [Configuration (`config.ini`)](#configuration-configini)
- [Scan profiles](#scan-profiles)
- [Report formats](#report-formats)
- [How it works](#how-it-works)
- [Contributing](#contributing)
- [License](#license)

---

## Features

- 🖥️ **Colorful interactive menu** (`rich` + `questionary`): launch scans,
  manage profiles, edit configuration, view the last report.
- 🎯 **Remembers your last target** — confirms it in one keypress next
  time, or lets you type a new one directly.
- 🕷️ **Multithreaded crawl**, limited to the same domain and a configurable
  number of pages.
- 🔗 **Classic redirect parameters** (`url`, `redirect`, `next`, `goto`...)
  tested on every link.
- 🧪 **Bypass payloads** (protocol-relative `//`, `@` trick, encoding, etc.)
  to catch variants that naive filters let through.
- 🧩 **JavaScript redirect detection** (`window.location.href`,
  `location.replace`).
- 📝 **Form scanning** by injecting the test URL into redirect fields.
- 🤖 **Optional `robots.txt` compliance**.
- 🔁 **Error and 429 handling** with exponential backoff and User-Agent
  rotation.
- 💾 **Reports** in TXT, JSON, CSV or HTML (openable in a browser).
- 🗂️ **Saved scan profiles** to reuse named setups.
- ⚙️ **`config.ini`** auto-generated and editable from the menu.

---

## Installation

Python 3.9 or higher is required.

```bash
git clone https://github.com/arditore/RedirectMe.git
cd RedirectMe
pip install -r requirements.txt
```

To contribute or run the tests, also install the dev dependencies:

```bash
pip install -r requirements-dev.txt
python -m pytest tests/ -v
```

---

## Usage

### Interactive menu

Launch the tool with no argument to open the menu:

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

1. Start a scan
2. Load a scan profile
3. Configuration
4. View last report
5. Quit
```

The menu walks you through it: target URL (or a one-keypress confirmation
of your last target — see below), scan options, authorization confirmation,
a live progress bar, then a colored summary and report generation.

Once you've scanned a site, RedirectMe remembers it: next time you start a
scan it asks *"Scan `<last target>` again?"* — confirm to reuse it
instantly, or decline to type a new URL directly. The chosen target is
saved to `config.ini` either way.

### Scriptable mode (CLI)

For automation/CI, pass the URL as an argument:

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
  target                Base URL of the site to scan (e.g.: https://example.com)

options:
  -h, --help            show this help message
  --no-interactive      force CLI mode (no interactive menu)
  --yes                 automatically confirm scan authorization
  --config CONFIG       path to the config.ini file (default: config.ini)
  --external-url URL    override the external test URL
  --max-pages N         override the max number of pages
  --output-format FMT   override the report format (txt, json, csv, html)
  --output-dir DIR      override the report output directory
  -v, --verbose         show detailed logs
```

---

## Configuration (`config.ini`)

Auto-generated on first launch (see `config.ini.example`):

```ini
[general]
external_url = https://evil.example.com
max_pages = 100
timeout = 5
min_delay = 0.2
max_delay = 0.8
max_workers = 5
last_target =

[scan]
use_bypass_payloads = true
respect_robots = false

[report]
default_format = html
output_dir = reports
```

Editable directly from the menu ("Configuration") or by modifying the file.

> ℹ️ `min_delay`/`max_delay` apply **to every individual HTTP request**
> (not per page). A page with many links and `use_bypass_payloads = true`
> can generate several hundred test requests — increase the delays to stay
> discreet, or disable `use_bypass_payloads` for a faster scan (1 payload
> tested per parameter instead of 6).

---

## Scan profiles

From the menu, save your current settings under a name ("quick-scan",
"full-scan"...) and reload them next time via "Load a scan profile".
Profiles are stored in `profiles/*.json`.

---

## Report formats

- **TXT**: simple list, one line per vulnerability.
- **JSON**: full structure (target, dates, stats, vulnerabilities) for
  integration with other tools.
- **CSV**: one line per vulnerability, for spreadsheets.
- **HTML**: styled report, automatically offered in the browser at the end
  of an interactive scan.

Reports are written to `reports/` (configurable).

---

## How it works

1. **Crawl**: the script starts from the target URL and follows internal
   links (same domain name only), up to `max_pages` pages, respecting
   `robots.txt` if enabled.
2. **Multithreaded injection**: for each link, every known parameter is
   tested with the external URL and, if enabled, its bypass variants.
3. **Verification**: an HTTP 3xx response whose `Location` header points to
   the external URL is considered an open redirect.
4. **JavaScript & forms**: the same principle is applied to redirects
   detected in JS code and in form fields.
5. **Report**: results are exported in the chosen format.

---

## Contributing

Contributions are welcome. Open an issue or a pull request to propose an
improvement or report a bug. Please include tests
(`python -m pytest tests/ -v`) for any new feature.

## License

Distributed under the [MIT](LICENSE) license.

---

🐧 *noot noot*
