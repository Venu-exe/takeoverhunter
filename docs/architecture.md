# Architecture

TakeoverHunter is a layered, zero-dependency Python toolkit.

```
CLI / Web Dashboard
        |
        v
   Scanner (orchestration, concurrency)
        |
   +----+----+----+
   |    |    |    |
   v    v    v    v
  DNS  HTTP  Enum  Fingerprint DB
        |
        v
   Storage (SQLite)  +  Report generators
```

## Modules
- `src/core/dns_resolver.py` — pure-Python DNS client (CNAME/A/AAAA), no dnspython.
- `src/core/http_checker.py` — HTTP/HTTPS fetch with SSL fallback.
- `src/core/enumerator.py` — crt.sh Certificate Transparency enumeration.
- `src/core/fingerprint_db.py` — service suffix + body fingerprint database (~45 services).
- `src/core/scanner.py` — thread-pool orchestration per host.
- `src/storage/db.py` — SQLite scan history.
- `src/report/generator.py` — JSON/CSV/Markdown/HTML reports.
- `src/api/server.py` — stdlib ThreadingHTTPServer + REST endpoints.
- `src/web/index.html` — single-page dashboard.
