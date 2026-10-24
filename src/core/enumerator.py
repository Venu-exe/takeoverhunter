"""Subdomain enumeration via Certificate Transparency (crt.sh)."""
import json
import ssl
import urllib.request


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
                            and "@" not in line
                            and all(c.isalnum() or c in ".-" for c in line)):
                        hosts.add(line)
    except Exception as e:
        raise RuntimeError(f"crt.sh enumeration failed: {e}")
    return sorted(hosts)
