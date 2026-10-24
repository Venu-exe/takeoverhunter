#!/usr/bin/env python3
"""TakeoverHunter CLI entrypoint."""
import argparse
import os
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
if BASE not in sys.path:
    sys.path.insert(0, BASE)

from src.core.scanner import Scanner
from src.core.enumerator import enumerate_crtsh
from src.report.generator import to_json, to_csv, to_markdown, to_html
from src.storage.db import ScanDB


def main():
    ap = argparse.ArgumentParser(description="TakeoverHunter - subdomain takeover detector")
    ap.add_argument("-l", "--list", help="File with hostnames (one per line)")
    ap.add_argument("-d", "--domain", help="Root domain: enumerate via crt.sh then check")
    ap.add_argument("-u", "--url", help="Single host to check")
    ap.add_argument("-t", "--threads", type=int, default=20)
    ap.add_argument("--timeout", type=int, default=8)
    ap.add_argument("--json", help="Write JSON results")
    ap.add_argument("--csv", help="Write CSV results")
    ap.add_argument("--report", help="Write Markdown report")
    ap.add_argument("--html", help="Write HTML report")
    ap.add_argument("--db", default="takeoverhunter.db", help="SQLite db path")
    ap.add_argument("--no-enum", action="store_true")
    ap.add_argument("--serve", action="store_true", help="Launch web dashboard")
    ap.add_argument("--port", type=int, default=8765)
    args = ap.parse_args()

    if args.serve:
        from src.api.server import run_server
        run_server(port=args.port, db_path=args.db,
                  web_dir=os.path.join(BASE, "src", "web"))
        return

    hosts = []
    if args.list:
        with open(args.list) as f:
            hosts = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    elif args.domain:
        if not args.no_enum:
            print(f"[*] Enumerating subdomains for {args.domain} via crt.sh...")
            try:
                hosts = enumerate_crtsh(args.domain)
                print(f"[*] Found {len(hosts)} unique hosts.")
            except Exception as e:
                print(f"[!] {e}")
                hosts = [args.domain]
        else:
            hosts = [args.domain]
    elif args.url:
        hosts = [args.url]
    else:
        ap.print_help()
        sys.exit(1)

    db = ScanDB(args.db)
    scan_id = db.start_scan(args.domain or (hosts[0] if len(hosts) == 1 else f"{len(hosts)} hosts"))
    scanner = Scanner(threads=args.threads, timeout=args.timeout)
    results = scanner.scan(hosts)
    for r in results:
        db.add_result(scan_id, r)
    db.finish_scan(scan_id, len(results), len(scanner.candidates))
    db.close()

    # console summary
    print(f"\nTotal checked: {len(results)} | Candidates: {len(scanner.candidates)}")
    for r in scanner.candidates:
        print(f"  ! {r['host']} -> {r['cname']} ({r['service']}, {r['confidence']})")

    if args.json:
        to_json(args.json, results)
        print(f"[+] JSON: {args.json}")
    if args.csv:
        to_csv(args.csv, results)
        print(f"[+] CSV: {args.csv}")
    if args.report:
        to_markdown(args.report, results, scanner.candidates)
        print(f"[+] Markdown: {args.report}")
    if args.html:
        to_html(args.html, results, scanner.candidates)
        print(f"[+] HTML: {args.html}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        sys.exit(130)
