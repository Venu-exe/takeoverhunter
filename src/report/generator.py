"""Report generators: JSON, CSV, Markdown, HTML."""
import csv
import json
import os


def to_json(path, results):
    with open(path, "w") as f:
        json.dump(results, f, indent=2)


def to_csv(path, results):
    keys = ["host", "cname", "http_status", "title", "service", "fingerprint", "confidence", "vulnerable"]
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
        w.writeheader()
        for r in results:
            w.writerow({k: r.get(k) for k in keys})


def to_markdown(path, results, candidates):
    lines = []
    lines.append("# Subdomain Takeover Report")
    lines.append("")
    lines.append(f"- Total hosts checked: {len(results)}")
    lines.append(f"- Takeover candidates: {len(candidates)}")
    lines.append("")
    if candidates:
        lines.append("## Candidates")
        lines.append("")
        lines.append("| Host | CNAME | Service | Confidence | Fingerprint |")
        lines.append("|------|-------|---------|------------|-------------|")
        for r in candidates:
            fp = (r.get("fingerprint") or "-").replace("|", "\\|")
            lines.append(f"| `{r['host']}` | `{r.get('cname')}` | {r.get('service')} | {r.get('confidence')} | {fp} |")
        lines.append("")
        for r in candidates:
            lines.append(f"### {r['host']}")
            lines.append("")
            lines.append(f"- **CNAME:** `{r.get('cname')}`")
            lines.append(f"- **Service:** {r.get('service')}")
            lines.append(f"- **Confidence:** {r.get('confidence')}")
            lines.append(f"- **HTTP status:** {r.get('http_status')}")
            lines.append(f"- **Action:** {r.get('note')}")
            lines.append("")
    else:
        lines.append("No takeover candidates found.")
    with open(path, "w") as f:
        f.write("\n".join(lines))


def to_html(path, results, candidates):
    rows = ""
    for r in candidates:
        rows += (f"<tr><td>{r['host']}</td><td>{r.get('cname')}</td>"
                 f"<td>{r.get('service')}</td><td>{r.get('confidence')}</td>"
                 f"<td>{r.get('fingerprint') or '-'}</td><td>{r.get('note')}</td></tr>")
    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Takeover Report</title>
<style>body{{font-family:sans-serif;margin:2rem}}table{{border-collapse:collapse;width:100%}}
th,td{{border:1px solid #ccc;padding:.5rem;text-align:left}}th{{background:#222;color:#fff}}</style>
</head><body>
<h1>Subdomain Takeover Report</h1>
<p>Total hosts: {len(results)} | Candidates: {len(candidates)}</p>
<table><tr><th>Host</th><th>CNAME</th><th>Service</th><th>Confidence</th><th>Fingerprint</th><th>Action</th></tr>
{rows}</table>
</body></html>"""
    with open(path, "w") as f:
        f.write(html)
