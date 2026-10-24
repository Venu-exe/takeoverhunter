# TakeoverHunter 🎯

Zero-dependency Python subdomain takeover detector — built as a final-year cybersecurity project.

## Features
- Subdomain enumeration via Certificate Transparency (crt.sh)
- Pure-Python DNS resolver (CNAME/A/AAAA) — no dnspython
- HTTP/HTTPS fingerprinting against ~45 takeover-prone services
- Confidence scoring (high/medium/low)
- SQLite scan history
- Web dashboard + REST API (stdlib only)
- JSON / CSV / Markdown / HTML reports
- Unit tests, Docker, docs

## Quick start
```bash
python takeoverhunter.py -d example.com
python takeoverhunter.py --serve   # dashboard at http://127.0.0.1:8765
```

## Tests
```bash
python -m pytest tests/ -q
```

## Docs
See `docs/` (architecture, methodology, user manual).

## License
MIT
