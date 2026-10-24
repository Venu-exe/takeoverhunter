# 🎯 TakeoverHunter

> **Zero-dependency Python subdomain takeover detector** — built as a final-year cybersecurity project.

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-6%20passing-brightgreen)](#testing)
[![Deps](https://img.shields.io/badge/dependencies-zero-blue)](#)
[![Docker](https://img.shields.io/badge/docker-ready-2496ED?logo=docker&logoColor=white)](Dockerfile)
[![GitHub stars](https://img.shields.io/github/stars/Venu-exe/takeoverhunter?style=social)](https://github.com/Venu-exe/takeoverhunter/stargazers)

TakeoverHunter detects **subdomain takeover** vulnerabilities by combining Certificate
Transparency enumeration, pure-Python DNS resolution, and HTTP fingerprinting against
**~45 takeover-prone services** (GitHub Pages, Heroku, AWS S3, Shopify, Azure, Vercel,
Netlify, CloudFront, Fastly, …). It ships with a web dashboard, REST API, SQLite
history, and multi-format reports — all with **zero external dependencies**.

---

## 📑 Table of Contents

- [Why this project](#why-this-project)
- [Features](#features)
- [Architecture](#architecture)
- [Quick start](#quick-start)
- [Usage](#usage)
- [Web dashboard](#web-dashboard)
- [Reports](#reports)
- [Confidence scoring](#confidence-scoring)
- [Services covered](#services-covered)
- [Testing](#testing)
- [Docker](#docker)
- [Project structure](#project-structure)
- [Documentation](#documentation)
- [Roadmap](#roadmap)
- [Disclaimer](#disclaimer)
- [License](#license)
- [Author](#author)

---

## 🤔 Why this project

Subdomain takeover is one of the most common and high-impact findings in bug bounty
programs. Existing tools either require heavy dependency stacks (Go, Ruby) or only
cover a handful of services. TakeoverHunter is a **self-contained, auditable,
educational** tool that a student can read end-to-end, run anywhere Python 3.8+
exists, and extend with new fingerprints in minutes.

## ✨ Features

| Area | Details |
|------|---------|
| Enumeration | crt.sh Certificate Transparency logs (no API key) |
| DNS | Built-in pure-Python resolver (CNAME / A / AAAA) — no `dnspython` |
| Fingerprinting | ~45 services with suffix + body fingerprint matching |
| Scoring | high / medium / low confidence per host |
| Concurrency | ThreadPoolExecutor (configurable) |
| Storage | SQLite scan history + per-host results |
| Dashboard | Single-page web UI + REST API (stdlib `http.server`) |
| Reports | JSON, CSV, Markdown, HTML |
| Deploy | Dockerfile + docker-compose ready |
| Tests | pytest unit tests (DNS, fingerprint, scanner) |
| Docs | Architecture, methodology, user manual |

## 🏗️ Architecture

```
CLI / Web Dashboard
        |
        v
   Scanner (orchestration, thread pool)
        |
   +----+----+----+----+
   |    |    |    |    |
   v    v    v    v    v
  DNS  HTTP  Enum  Fingerprint  Storage
                              (SQLite)
        |
        v
   Report generators (JSON/CSV/MD/HTML)
```

See [`docs/architecture.md`](docs/architecture.md) for details.

## 🚀 Quick start

```bash
git clone https://github.com/Venu-exe/takeoverhunter.git
cd takeoverhunter

# scan a domain (enumerates subdomains via crt.sh)
python3 takeoverhunter.py -d example.com

# scan a host list
python3 takeoverhunter.py -l hosts.txt

# single host
python3 takeoverhunter.py -u sub.example.com
```

No `pip install` required — standard library only.

## 🖥️ Usage

```
python takeoverhunter.py [-l FILE] [-d DOMAIN] [-u HOST]
                         [-t THREADS] [--timeout N]
                         [--json F] [--csv F] [--report F] [--html F]
                         [--db PATH] [--serve] [--port N]
```

| Flag | Description |
|------|-------------|
| `-l, --list` | File with hostnames (one per line) |
| `-d, --domain` | Root domain → enumerate via crt.sh then check |
| `-u, --url` | Single host to check |
| `-t, --threads` | Concurrency (default 20) |
| `--timeout` | HTTP/DNS timeout seconds (default 8) |
| `--json/--csv/--report/--html` | Write report in that format |
| `--db` | SQLite db path (default `takeoverhunter.db`) |
| `--serve` | Launch web dashboard |
| `--port` | Dashboard port (default 8765) |

## 🌐 Web dashboard

```bash
python3 takeoverhunter.py --serve --port 8765
# open http://127.0.0.1:8765
```

Features: run scans from the browser, view results + confidence badges, scan history.

## 📄 Reports

```bash
python3 takeoverhunter.py -l hosts.txt \
  --json out.json --csv out.csv --report out.md --html out.html
```

## 🎚️ Confidence scoring

| Level | Condition |
|-------|-----------|
| **high** | Service fingerprint found in HTTP response (strong takeover signal) |
| **medium** | CNAME points to a known service **and** HTTP returns 404/403/410/502/503 |
| **low** | CNAME points to a known service, no fingerprint/error signal |

## 🧩 Services covered

GitHub Pages · Heroku · AWS S3 · Shopify · Azure Web Apps · Fastly · Tumblr ·
WordPress.com · Ghost · Pantheon · Zendesk · UserVoice · Surge.sh · Bitbucket ·
Webflow · Netlify · Vercel · Readme.io · Cargo · Statuspage · HelpScout ·
HelpJuice · Intercom · Tilda · Smartling · Acquia · Proposify · Simplebooklet ·
GetResponse · Tictail · Campaign Monitor · Unbounce · Strikingly · LaunchRock ·
Aftership · Pingdom · Tave · Formstack · JetBrains · Freshdesk · Desk.com ·
CloudFront · Azure Traffic Manager · AWS Elastic Beanstalk · Fly.io · Render · Kinsta

## 🧪 Testing

```bash
python -m pytest tests/ -q
# 6 passed
```

## 🐳 Docker

```bash
docker build -t takeoverhunter .
docker run -p 8765:8765 -v $(pwd)/data:/data takeoverhunter
```

## 📁 Project structure

```
takeoverhunter/
├── takeoverhunter.py          # CLI entrypoint
├── src/
│   ├── core/                  # DNS, HTTP, enumerator, fingerprints, scanner
│   ├── storage/               # SQLite
│   ├── report/                # JSON/CSV/MD/HTML generators
│   ├── api/                   # REST server
│   └── web/                   # dashboard (index.html)
├── tests/                     # pytest
├── docs/                      # architecture, methodology, user manual
├── Dockerfile
├── Makefile
└── requirements.txt           # (empty — zero deps)
```

## 📚 Documentation

- [`docs/architecture.md`](docs/architecture.md)
- [`docs/methodology.md`](docs/methodology.md)
- [`docs/user_manual.md`](docs/user_manual.md)

## 🗺️ Roadmap

- [ ] Benchmark vs `subjack` / `subzy` / `nuclei` (precision/recall)
- [ ] PDF report export
- [ ] More services + community fingerprint contributions
- [ ] GitHub Actions CI
- [ ] Authenticated scanning / rate limiting

## ⚠️ Disclaimer

Only run against targets you are **authorized** to test. This tool is for educational
and authorized bug-bounty use. The author is not responsible for misuse.

## 📜 License

MIT — see [LICENSE](LICENSE).

## 👤 Author

**Venu-exe** — cybersecurity student & bug bounty hunter

- GitHub: [@Venu-exe](https://github.com/Venu-exe)
- Project: [takeoverhunter](https://github.com/Venu-exe/takeoverhunter)

---

> ⭐ If this helped you, consider starring the repo!
