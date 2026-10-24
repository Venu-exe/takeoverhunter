#!/usr/bin/env python3
"""
TakeoverHunter - Subdomain Takeover Detection Tool
=================================================
Zero-dependency Python tool for bug bounty hunters.

Given a list of hostnames (or a root domain), it:
  * enumerates subdomains via Certificate Transparency (crt.sh) [optional]
  * resolves CNAME chains (pure-Python DNS, no dnspython needed)
  * fingerprints HTTP responses against ~45 takeover-prone services
  * reports takeover candidates with proof (CNAME + matched fingerprint)

Usage:
  python takeoverhunter.py -l hosts.txt
  python takeoverhunter.py -d example.com
  python takeoverhunter.py -u sub.example.com
  python takeoverhunter.py -l hosts.txt --json out.json --csv out.csv --report out.md

Author: Venu-exe  |  License: MIT
"""
import argparse
import csv
import json
import socket
import ssl
import struct
import sys
import threading
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed

# --------------------------------------------------------------------------- #
# ANSI colors
# --------------------------------------------------------------------------- #
def C(s, code): return f"\033[{code}m{s}\033[0m"
RED, GREEN, YELLOW, BLUE, CYAN, MAGENTA, BOLD, DIM = "31", "32", "33", "34", "36", "35", "1", "2"
def red(s): return C(s, RED)
def green(s): return C(s, GREEN)
def yellow(s): return C(s, YELLOW)
def blue(s): return C(s, BLUE)
def cyan(s): return C(s, CYAN)
def magenta(s): return C(s, MAGENTA)
def bold(s): return C(s, BOLD)
def dim(s): return C(s, DIM)

# --------------------------------------------------------------------------- #
# Service fingerprint database
# Each entry: (service_name, cname_suffixes, http_fingerprints, notes)
#   cname_suffixes: list of lowercase suffixes the CNAME must end with
#   http_fingerprints: list of substrings that, if found in body, indicate
#                      a dangling/unclaimed resource (takeover possible)
# --------------------------------------------------------------------------- #
SERVICES = [
    ("GitHub Pages", [".github.io", "github.io"], ["There isn't a GitHub Pages site here", "404 There isn't a GitHub Pages site here"], "Create repo named <user>.github.io or CNAME file."),
    ("Heroku", [".herokuapp.com", ".herokussl.com", "heroku.com"], ["No such app", "herokucdn.com/error-pages/no-such-app.html", "There's nothing here, yet."], "Create Heroku app with matching name."),
    ("AWS S3", [".s3.amazonaws.com", ".s3-website", "s3.amazonaws.com"], ["NoSuchBucket", "The specified bucket does not exist", "BucketNotFound"], "Create S3 bucket with matching name."),
    ("Shopify", [".myshopify.com"], ["Sorry, this shop is currently unavailable", "Only one shop per domain", "Sorry, this shop is currently unavailable."], "Claim shop name."),
    ("Azure Web Apps", [".azurewebsites.net"], ["404 Web Site not found", "Error 404 - Web app not found"], "Create Azure web app."),
    ("Fastly", [".fastly.net"], ["Fastly error: unknown domain", "Please check that this domain has been added to a service"], "Add domain to Fastly service."),
    ("Tumblr", [".tumblr.com"], ["There's nothing here", "Whatever you were looking for doesn't currently exist at this address", "tumblr.com/register"], "Claim Tumblr blog."),
    ("WordPress.com", [".wordpress.com"], ["Do you want to register", "doesn't exist", "is no longer available"], "Register WordPress site."),
    ("Ghost", [".ghost.io"], ["The thing you were looking for is no longer here", "Ghost"], "Claim Ghost publication."),
    ("Pantheon", [".pantheonsite.io"], ["The gods are wise", "404 error unknown site", "No site configured"], "Claim Pantheon site."),
    ("Zendesk", [".zendesk.com"], ["Help Center Closed", "Oops, this help center no longer exists", "This help center no longer exists"], "Claim Zendesk subdomain."),
    ("UserVoice", [".uservoice.com"], ["This UserVoice subdomain is currently available", "uservoice.com"], "Claim UserVoice portal."),
    ("Surge.sh", [".surge.sh"], ["project not found"], "surge deploy."),
    ("Bitbucket", [".bitbucket.io"], ["Repository not found"], "Create Bitbucket repo."),
    ("Webflow", [".webflow.io"], ["The page you are looking for doesn't exist or has been moved"], "Claim Webflow site."),
    ("Netlify", [".netlify.app", ".netlify.com"], ["Not Found - Request ID", "Page not found"], "Claim Netlify site."),
    ("Vercel", [".vercel.app"], ["The deployment could not be found", "404: NOT_FOUND", "DEPLOYMENT_NOT_FOUND"], "Claim Vercel project."),
    ("Readme.io", [".readme.io"], ["Project not found", "readme.io"], "Claim Readme project."),
    ("Cargo", [".cargocollective.com"], ["404 Not Found"], "Claim Cargo site."),
    ("Statuspage", [".statuspage.io"], ["Status page not found", "You are being redirected"], "Claim Statuspage."),
    ("HelpScout", [".helpscoutdocs.com"], ["No settings were found for this company"], "Claim HelpScout mailbox."),
    ("HelpJuice", [".helpjuice.com"], ["We could not find what you're looking for"], "Claim HelpJuice KB."),
    ("Intercom", [".intercom.io"], ["This page is reserved for artistic dogs", "Uh oh. That page doesn't exist", "intercom.com"], "Claim Intercom."),
    ("Tilda", [".tilda.ws"], ["Please renew your subscription"], "Claim Tilda site."),
    ("Smartling", [".smartling.com"], ["Domain is not configured"], "Claim Smartling project."),
    ("Acquia", [".acquia-sites.com"], ["The site you are looking for could not be found"], "Claim Acquia site."),
    ("Proposify", [".proposify.biz"], ["If you need immediate assistance"], "Claim Proposify."),
    ("Simplebooklet", [".simplebooklet.com"], ["We can't find this SimpleBooklet"], "Claim Simplebooklet."),
    ("GetResponse", [".getresponse.com"], ["Oops, something went wrong"], "Claim GetResponse."),
    ("Tictail", [".tictail.com"], ["Start selling on Tictail", "to target URL"], "Claim Tictail store."),
    ("Campaign Monitor", [".createsend.com"], ["Trying to access your account?"], "Claim Campaign Monitor."),
    ("Unbounce", [".unbounce.com"], ["The requested URL was not found on this server"], "Claim Unbounce page."),
    ("Strikingly", [".strikingly.com"], ["But if you're looking to build a stunning website"], "Claim Strikingly site."),
    ("LaunchRock", [".launchrock.com"], ["It looks like you may have taken a wrong turn"], "Claim LaunchRock."),
    ("Aftership", [".aftership.com"], ["Oops. The page you're looking for doesn't exist"], "Claim Aftership."),
    ("Pingdom", [".pingdom.com"], ["Sorry, we couldn't find the status page"], "Claim Pingdom status page."),
    ("Tave", [".tave.com"], ["Sorry, this page is no longer available"], "Claim Tave."),
    ("Formstack", [".formstack.com"], ["Oops! This page is no longer available"], "Claim Formstack."),
    ("JetBrains", [".myjetbrains.com"], ["is not a registered InCloud YouTrack"], "Claim JetBrains."),
    ("Freshdesk", [".freshdesk.com"], ["There is no helpdesk here", "freshdesk.com"], "Claim Freshdesk."),
    ("Desk.com", [".desk.com"], ["Sorry, we couldn't find your site"], "Claim Desk."),
    ("CloudFront", [".cloudfront.net"], ["Bad request", "ERROR: The request could not be satisfied", "The request could not be satisfied"], "Claim CloudFront distribution (rare; usually needs dangling origin)."),
    ("Azure Traffic Manager", [".trafficmanager.net"], ["Page not found"], "Claim Traffic Manager profile."),
    ("AWS Elastic Beanstalk", [".elasticbeanstalk.com"], ["404", "There is no application"], "Claim EB environment."),
    ("Fly.io", [".fly.dev"], ["404 Not Found", "app not found"], "Claim Fly app."),
    ("Render", [".onrender.com"], ["Not Found", "Service not found"], "Claim Render service."),
    ("Kinsta", [".kinsta.cloud"], ["No site configured"], "Claim Kinsta site."),
]

# --------------------------------------------------------------------------- #
# Pure-python DNS resolver (CNAME + A)
# --------------------------------------------------------------------------- #
DNS_SERVERS = ["8.8.8.8", "1.1.1.1"]


def _dns_query(name, qtype, timeout=4):
    """Return list of (type, value) tuples for the given name/qtype."""
    results = []
    for server in DNS_SERVERS:
        try:
            # build packet
            tid = 0x1234
            flags = 0x0100  # RD
            header = struct.pack("!HHHHHH", tid, flags, 1, 0, 0, 0)
            qname = b"".join(bytes([len(part)]) + part.encode() for part in name.rstrip(".").split(".")) + b"\x00"
            question = qname + struct.pack("!HH", qtype, 1)  # type, class IN
            packet = header + question
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(packet, (server, 53))
            data, _ = sock.recvfrom(512)
            sock.close()
        except Exception:
            continue
        # parse
        if len(data) < 12:
            continue
        tid_r, flags_r, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
        off = 12
        # skip questions
        for _ in range(qd):
            off = _skip_name(data, off)
            off += 4  # type + class
        # parse answers
        for _ in range(an):
            name_off = off
            off = _skip_name(data, off)
            if off + 10 > len(data):
                break
            rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", data[off:off+10])
            off += 10
            rdata_start = off
            if rtype == 5:  # CNAME
                cname = _decode_name(data, off)
                results.append((5, cname))
            elif rtype == 1 and rdlen == 4:  # A
                ip = socket.inet_ntoa(data[off:off+4])
                results.append((1, ip))
            elif rtype == 28 and rdlen == 16:  # AAAA
                ip = socket.inet_ntop(socket.AF_INET6, data[off:off+16])
                results.append((28, ip))
            off += rdlen
        if results:
            return results
    return results


def _skip_name(data, off):
    while True:
        if off >= len(data):
            return off
        length = data[off]
        if length == 0:
            return off + 1
        if (length & 0xC0) == 0xC0:
            return off + 2
        off += length + 1


def _decode_name(data, off):
    labels = []
    jumped = False
    original_off = off
    safety = 0
    while safety < 64:
        safety += 1
        if off >= len(data):
            break
        length = data[off]
        if length == 0:
            off += 1
            break
        if (length & 0xC0) == 0xC0:
            if off + 1 >= len(data):
                break
            ptr = ((length & 0x3F) << 8) | data[off + 1]
            if not jumped:
                original_off = off + 2
            off = ptr
            jumped = True
            continue
        off += 1
        labels.append(data[off:off + length].decode("ascii", "replace"))
        off += length
    if jumped:
        off = original_off
    return ".".join(labels).rstrip(".") + "."


def resolve_cname(host, timeout=4):
    """Resolve CNAME chain for host. Returns (final_cname_or_None, ip_list)."""
    chain = []
    current = host.rstrip(".")
    seen = set()
    ip_list = []
    for _ in range(10):
        if current in seen:
            break
        seen.add(current)
        answers = _dns_query(current, 5, timeout)  # CNAME
        cname_found = None
        for typ, val in answers:
            if typ == 5:
                cname_found = val.rstrip(".")
                break
        if cname_found and cname_found.lower() != current.lower():
            chain.append(cname_found)
            current = cname_found
            continue
        # no CNAME; get A
        a_answers = _dns_query(current, 1, timeout)
        for typ, val in a_answers:
            if typ == 1:
                ip_list.append(val)
        break
    final_cname = chain[-1] if chain else None
    # if host itself had CNAME, first in chain is the immediate CNAME
    immediate = chain[0] if chain else None
    return immediate, chain, ip_list


# --------------------------------------------------------------------------- #
# HTTP fetch
# --------------------------------------------------------------------------- #
def http_fetch(host, timeout=8):
    """Fetch http/https body. Returns (status, body_str, final_url)."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}/"
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0 (TakeoverHunter)",
                "Accept": "*/*",
            })
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                raw = resp.read(65536)
                body = raw.decode("utf-8", "replace")
                return resp.status, body, resp.geturl()
        except urllib.error.HTTPError as e:
            try:
                body = e.read(65536).decode("utf-8", "replace")
            except Exception:
                body = ""
            return e.code, body, url
        except Exception:
            continue
    return None, "", ""


# --------------------------------------------------------------------------- #
# crt.sh enumeration
# --------------------------------------------------------------------------- #
def enumerate_crtsh(domain, timeout=30):
    hosts = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        ctx = ssl.create_default_context()
        req = urllib.request.Request(url, headers={"User-Agent": "TakeoverHunter"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
        for row in data:
            for field in ("name_value", "common_name"):
                val = row.get(field, "")
                for line in str(val).splitlines():
                    line = line.strip().lower()
                    if line.startswith("*."):
                        line = line[2:]
                    if (line and "." in line and " " not in line
                            and "@" not in line and all(c.isalnum() or c in ".-" for c in line)):
                        hosts.add(line)
    except Exception as e:
        print(yellow(f"[!] crt.sh enumeration failed: {e}"))
    return sorted(hosts)


# --------------------------------------------------------------------------- #
# Matching
# --------------------------------------------------------------------------- #
def match_service(cname, body, status):
    if not cname:
        return None
    cl = cname.lower()
    for svc_name, suffixes, fingerprints, note in SERVICES:
        if any(cl.endswith(suf.lower().lstrip(".")) or cl == suf.lower().lstrip(".") or cl.endswith(suf.lower()) for suf in suffixes):
            # suffix check: cname ends with suffix
            pass
        # proper suffix match
        matched_suffix = None
        for suf in suffixes:
            s = suf.lower().lstrip(".")
            if cl == s or cl.endswith("." + s) or cl.endswith(s):
                matched_suffix = suf
                break
        if not matched_suffix:
            continue
        # fingerprint match
        fp_hit = None
        for fp in fingerprints:
            if fp.lower() in (body or "").lower():
                fp_hit = fp
                break
        confidence = "high" if fp_hit else ("medium" if status in (404, 403, 410, 502, 503) else "low")
        return {
            "service": svc_name,
            "suffix": matched_suffix,
            "fingerprint": fp_hit,
            "note": note,
            "confidence": confidence,
        }
    return None


# --------------------------------------------------------------------------- #
# Per-host check
# --------------------------------------------------------------------------- #
lock = threading.Lock()
results = []


def check_host(host):
    host = host.strip().lower()
    if not host or host.startswith("#"):
        return None
    # strip scheme if present
    if "://" in host:
        host = host.split("://", 1)[1].split("/")[0]
    immediate, chain, ips = resolve_cname(host)
    cname = immediate
    status, body, final_url = http_fetch(host)
    svc = match_service(cname, body, status)
    title = ""
    if body:
        import re
        m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        if m:
            title = m.group(1).strip()[:80]

    vulnerable = svc is not None and (svc["fingerprint"] is not None or svc["confidence"] in ("high", "medium"))

    rec = {
        "host": host,
        "cname": cname,
        "cname_chain": chain,
        "ips": ips,
        "http_status": status,
        "title": title,
        "service": svc["service"] if svc else None,
        "fingerprint": svc["fingerprint"] if svc else None,
        "confidence": svc["confidence"] if svc else None,
        "note": svc["note"] if svc else None,
        "vulnerable": bool(vulnerable and svc),
    }

    with lock:
        results.append(rec)

    # console output
    if svc:
        conf_color = {"high": red, "medium": yellow, "low": dim}[svc["confidence"]]
        print(f"{bold(host):<40} {cyan('->')} {magenta(cname or '-')}  "
              f"[{conf_color(svc['confidence'].upper())}] {green(svc['service'])}"
              + (f"  fp={dim(svc['fingerprint'][:40])}" if svc["fingerprint"] else ""))
    else:
        print(f"{host:<40} {dim('->')} {dim(cname or 'no-cname')}  {dim('no match')}")
    return rec


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main():
    global results
    ap = argparse.ArgumentParser(description="Subdomain takeover detector (zero deps)")
    ap.add_argument("-l", "--list", help="File with hostnames (one per line)")
    ap.add_argument("-d", "--domain", help="Root domain: enumerate subdomains via crt.sh then check")
    ap.add_argument("-u", "--url", help="Single host to check")
    ap.add_argument("-t", "--threads", type=int, default=20, help="Concurrency (default 20)")
    ap.add_argument("--timeout", type=int, default=8, help="HTTP/DNS timeout seconds")
    ap.add_argument("--json", help="Write JSON results to file")
    ap.add_argument("--csv", help="Write CSV results to file")
    ap.add_argument("--report", help="Write Markdown report to file")
    ap.add_argument("--no-enum", action="store_true", help="Skip crt.sh enumeration for -d")
    args = ap.parse_args()

    hosts = []
    if args.list:
        with open(args.list) as f:
            hosts = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    elif args.domain:
        if not args.no_enum:
            print(cyan(f"[*] Enumerating subdomains for {args.domain} via crt.sh..."))
            hosts = enumerate_crtsh(args.domain)
            print(cyan(f"[*] Found {len(hosts)} unique hosts."))
        else:
            hosts = [args.domain]
    elif args.url:
        hosts = [args.url]
    else:
        ap.print_help()
        sys.exit(1)

    # dedup
    seen = set()
    uniq = []
    for h in hosts:
        h = h.strip().lower()
        if h and h not in seen:
            seen.add(h)
            uniq.append(h)
    hosts = uniq

    print(bold(f"\n[*] Checking {len(hosts)} hosts with {args.threads} threads...\n"))

    results = []
    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futs = {ex.submit(check_host, h): h for h in hosts}
        for fut in as_completed(futs):
            try:
                fut.result()
            except Exception as e:
                print(red(f"[!] Error: {e}"))

    # summary
    vulns = [r for r in results if r and r.get("vulnerable")]
    print("\n" + bold("=" * 70))
    print(bold(f"  Total checked : {len(results)}"))
    print(bold(f"  Candidates    : {len(vulns)}") + (red("  <-- investigate!") if vulns else green("  (none)")))
    print(bold("=" * 70))

    if vulns:
        print("\n" + red(bold("TAKEOVER CANDIDATES:")))
        for r in vulns:
            print(f"  {red('!')} {bold(r['host'])}")
            print(f"      CNAME : {r['cname']}")
            print(f"      Service: {r['service']}  (confidence: {r['confidence']})")
            if r["fingerprint"]:
                print(f"      Proof  : fingerprint '{r['fingerprint']}' found in response")
            print(f"      Action : {r['note']}")
            print()

    # outputs
    if args.json:
        with open(args.json, "w") as f:
            json.dump(results, f, indent=2)
        print(green(f"[+] JSON written to {args.json}"))
    if args.csv:
        if results:
            keys = ["host", "cname", "http_status", "title", "service", "fingerprint", "confidence", "vulnerable"]
            with open(args.csv, "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
                w.writeheader()
                for r in results:
                    w.writerow({k: r.get(k) for k in keys})
        print(green(f"[+] CSV written to {args.csv}"))
    if args.report:
        write_report(args.report, results, vulns)
        print(green(f"[+] Report written to {args.report}"))


def write_report(path, results, vulns):
    lines = []
    lines.append("# Subdomain Takeover Report")
    lines.append("")
    lines.append(f"- Total hosts checked: {len(results)}")
    lines.append(f"- Takeover candidates: {len(vulns)}")
    lines.append("")
    if vulns:
        lines.append("## Candidates")
        lines.append("")
        lines.append("| Host | CNAME | Service | Confidence | Fingerprint |")
        lines.append("|------|-------|---------|------------|-------------|")
        for r in vulns:
            fp = (r["fingerprint"] or "-").replace("|", "\\|")
            lines.append(f"| `{r['host']}` | `{r['cname']}` | {r['service']} | {r['confidence']} | {fp} |")
        lines.append("")
        for r in vulns:
            lines.append(f"### {r['host']}")
            lines.append("")
            lines.append(f"- **CNAME:** `{r['cname']}`")
            lines.append(f"- **Service:** {r['service']}")
            lines.append(f"- **Confidence:** {r['confidence']}")
            lines.append(f"- **HTTP status:** {r['http_status']}")
            lines.append(f"- **Action:** {r['note']}")
            lines.append("")
    else:
        lines.append("No takeover candidates found.")
    with open(path, "w") as f:
        f.write("\n".join(lines))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n" + yellow("[!] Interrupted."))
        sys.exit(130)
