# 🔀 RedirectMe

**Scanner de redirections ouvertes (open redirect) pour l'audit de sécurité web.**

[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

RedirectMe explore un site web et teste ses liens, ses scripts JavaScript et
ses formulaires afin de détecter des **redirections ouvertes** — une faille
souvent exploitée dans des campagnes de **phishing**, où une URL en apparence
légitime redirige finalement vers un site malveillant.

> ⚠️ **Usage éthique uniquement.** N'utilisez cet outil que sur des sites que
> vous possédez ou pour lesquels vous avez une autorisation explicite (test
> d'intrusion, bug bounty, CTF). Scanner un site tiers sans accord est illégal
> dans la plupart des juridictions.

---

## Sommaire

- [Fonctionnalités](#fonctionnalités)
- [Installation](#installation)
- [Utilisation](#utilisation)
- [Options](#options)
- [Exemple de sortie](#exemple-de-sortie)
- [Comment ça marche](#comment-ça-marche)
- [Contribuer](#contribuer)
- [Licence](#licence)

---

## Fonctionnalités

- 🕷️ **Crawl automatique** du site à partir d'une URL de départ, limité au même domaine et à un nombre de pages configurable.
- 🔗 **Test des paramètres de redirection** (`url`, `redirect`, `next`, `return`, `goto`, etc.) sur chaque lien découvert.
- 🧩 **Détection des redirections JavaScript** (`window.location.href`, `location.replace`).
- 📝 **Scan des formulaires** en injectant l'URL de test dans les champs de redirection.
- 🔁 **Gestion des erreurs et des 429** (rate limiting) avec backoff exponentiel et rotation de User-Agent.
- 💾 **Export des résultats** dans un fichier texte.

---

## Installation

Python 3.9 ou supérieur est requis.

```bash
git clone https://github.com/arditore/RedirectMe.git
cd RedirectMe
pip install -r requirements.txt
```

---

## Utilisation

```bash
python main.py https://example.com
```

L'outil explore automatiquement le site et affiche les redirections ouvertes détectées.

## Options

```
usage: main.py [-h] [--external-url EXTERNAL_URL] [--max-pages MAX_PAGES]
                [--timeout TIMEOUT] [--min-delay MIN_DELAY]
                [--max-delay MAX_DELAY] [--output OUTPUT] [-v]
                target

positional arguments:
  target                URL de base du site à scanner (ex : https://example.com)

options:
  -h, --help            affiche ce message d'aide
  --external-url URL    URL externe utilisée pour détecter une redirection ouverte
                         (défaut : https://evil.example.com)
  --max-pages N         nombre maximum de pages à explorer (défaut : 100)
  --timeout N           timeout HTTP en secondes (défaut : 5)
  --min-delay N         délai minimum (s) entre deux pages (défaut : 2.0)
  --max-delay N         délai maximum (s) entre deux pages (défaut : 5.0)
  --output FILE         fichier dans lequel enregistrer les vulnérabilités trouvées
  -v, --verbose         affiche les logs détaillés (pages sûres incluses)
```

Exemple avec options :

```bash
python main.py https://example.com --max-pages 50 --output rapport.txt -v
```

---

## Exemple de sortie

```
Scan de https://example.com à la recherche de redirections ouvertes...

Scan de https://example.com (1/100)
[VULNÉRABLE] https://example.com/path?url=https://evil.example.com redirige vers https://evil.example.com
...

3 redirection(s) ouverte(s) détectée(s) sur 42 page(s) explorée(s).
Résultats enregistrés dans rapport.txt
```

---

## Comment ça marche

1. **Crawl** : le script part de l'URL cible et suit les liens internes (même nom de domaine uniquement), jusqu'à `--max-pages` pages.
2. **Injection** : pour chaque lien, chaque paramètre connu (`REDIRECT_PARAMS`) est testé avec l'URL externe comme valeur.
3. **Vérification** : une réponse HTTP 3xx dont l'en-tête `Location` pointe vers l'URL externe est considérée comme une redirection ouverte.
4. **JavaScript & formulaires** : le même principe est appliqué aux redirections détectées dans le code JS et aux champs de formulaire.

---

## Contribuer

Les contributions sont bienvenues. Ouvrez une issue ou une pull request pour proposer une amélioration ou signaler un bug.

## Licence

Distribué sous licence [MIT](LICENSE).
