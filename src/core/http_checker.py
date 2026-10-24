"""HTTP fetcher with SSL fallback."""
import ssl
import urllib.request
import urllib.error
import re


def http_fetch(host, timeout=8):
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
                title = _title(body)
                return resp.status, body, resp.geturl(), title
        except urllib.error.HTTPError as e:
            try:
                body = e.read(65536).decode("utf-8", "replace")
            except Exception:
                body = ""
            return e.code, body, url, _title(body)
        except Exception:
            continue
    return None, "", "", ""


def _title(body):
    if not body:
        return ""
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    return m.group(1).strip()[:120] if m else ""
