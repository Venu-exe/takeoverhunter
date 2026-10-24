"""Scan orchestration: ties DNS + HTTP + fingerprinting together."""
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from .dns_resolver import resolve_cname
from .http_checker import http_fetch
from .fingerprint_db import match_service


class Scanner:
    def __init__(self, threads=20, timeout=8, dns_servers=None):
        self.threads = threads
        self.timeout = timeout
        self.dns_servers = dns_servers
        self.results = []
        self._lock = threading.Lock()

    def check_host(self, host):
        host = host.strip().lower()
        if not host or host.startswith("#"):
            return None
        if "://" in host:
            host = host.split("://", 1)[1].split("/")[0]
        immediate, chain, ips = resolve_cname(host, timeout=self.timeout, servers=self.dns_servers)
        status, body, final_url, title = http_fetch(host, timeout=self.timeout)
        svc = match_service(immediate, body, status)
        vulnerable = bool(svc and (svc["fingerprint"] is not None
                                  or svc["confidence"] in ("high", "medium")))
        rec = {
            "host": host,
            "cname": immediate,
            "cname_chain": chain,
            "ips": ips,
            "http_status": status,
            "title": title,
            "final_url": final_url,
            "service": svc["service"] if svc else None,
            "fingerprint": svc["fingerprint"] if svc else None,
            "confidence": svc["confidence"] if svc else None,
            "note": svc["note"] if svc else None,
            "vulnerable": vulnerable,
        }
        with self._lock:
            self.results.append(rec)
        return rec

    def scan(self, hosts):
        self.results = []
        uniq = []
        seen = set()
        for h in hosts:
            h = h.strip().lower()
            if h and h not in seen:
                seen.add(h)
                uniq.append(h)
        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futs = {ex.submit(self.check_host, h): h for h in uniq}
            for fut in as_completed(futs):
                try:
                    fut.result()
                except Exception:
                    pass
        return self.results

    @property
    def candidates(self):
        return [r for r in self.results if r and r.get("vulnerable")]
