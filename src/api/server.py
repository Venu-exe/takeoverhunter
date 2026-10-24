"""Lightweight HTTP API + dashboard server (stdlib only)."""
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from src.core.scanner import Scanner
from src.core.enumerator import enumerate_crtsh
from src.storage.db import ScanDB


class Handler(BaseHTTPRequestHandler):
    db = None
    web_dir = None

    def _json(self, obj, code=200):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _file(self, path, ctype):
        full = os.path.join(self.web_dir, path.lstrip("/"))
        if not os.path.isfile(full):
            self.send_error(404)
            return
        with open(full, "rb") as f:
            data = f.read()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        p = urlparse(self.path)
        if p.path == "/" or p.path == "/index.html":
            self._file("index.html", "text/html")
            return
        if p.path == "/api/scans":
            self._json(self.db.list_scans())
            return
        if p.path.startswith("/api/scan/"):
            sid = p.path.split("/")[-1]
            try:
                sid = int(sid)
            except ValueError:
                self._json({"error": "bad id"}, 400)
                return
            res = self.db.get_scan(sid)
            if res is None:
                self._json({"error": "not found"}, 404)
            else:
                self._json(res)
            return
        self.send_error(404)

    def do_POST(self):
        p = urlparse(self.path)
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode() if length else ""
        try:
            payload = json.loads(body) if body else {}
        except Exception:
            payload = {}
        if p.path == "/api/scan":
            hosts = payload.get("hosts", [])
            domain = payload.get("domain")
            if domain and not hosts:
                try:
                    hosts = enumerate_crtsh(domain)
                except Exception as e:
                    self._json({"error": str(e)}, 500)
                    return
            if not hosts:
                self._json({"error": "no hosts"}, 400)
                return
            target = domain or (hosts[0] if len(hosts) == 1 else f"{len(hosts)} hosts")
            scan_id = self.db.start_scan(target)
            scanner = Scanner(threads=payload.get("threads", 20),
                             timeout=payload.get("timeout", 8))
            results = scanner.scan(hosts)
            for r in results:
                self.db.add_result(scan_id, r)
            self.db.finish_scan(scan_id, len(results), len(scanner.candidates))
            self._json({"scan_id": scan_id, "total": len(results),
                        "candidates": len(scanner.candidates), "results": results})
            return
        self.send_error(404)

    def log_message(self, *a):
        pass


def run_server(host="127.0.0.1", port=8765, db_path="takeoverhunter.db", web_dir=None):
    if web_dir is None:
        web_dir = os.path.join(os.path.dirname(__file__), "..", "web")
        web_dir = os.path.abspath(web_dir)
    Handler.db = ScanDB(db_path)
    Handler.web_dir = web_dir
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"TakeoverHunter dashboard: http://{host}:{port}")
    try:
        httpd.serve_forever()
    finally:
        Handler.db.close()
