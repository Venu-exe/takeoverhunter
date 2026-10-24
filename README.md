# TakeoverHunter 🎯

Zero-dependency Python subdomain takeover detector for bug bounty hunters.

Given a list of hostnames (or a root domain), it:
- enumerates subdomains via Certificate Transparency (crt.sh)
- resolves CNAME chains using a built-in pure-Python DNS client (no dnspython)
- fingerprints HTTP responses against ~45 takeover-prone services
- reports takeover candidates with proof (CNAME + matched fingerprint)

## Services covered
GitHub Pages, Heroku, AWS S3, Shopify, Azure Web Apps, Fastly, Tumblr, WordPress.com, Ghost, Pantheon, Zendesk, UserVoice, Surge.sh, Bitbucket, Webflow, Netlify, Vercel, Readme.io, Cargo, Statuspage, HelpScout, HelpJuice, Intercom, Tilda, Smartling, Acquia, Proposify, Simplebooklet, GetResponse, Tictail, Campaign Monitor, Unbounce, Strikingly, LaunchRock, Aftership, Pingdom, Tave, Formstack, JetBrains, Freshdesk, Desk.com, CloudFront, Azure Traffic Manager, AWS Elastic Beanstalk, Fly.io, Render, Kinsta.

## Usage
```bash
# from a host list
python takeoverhunter.py -l hosts.txt

# enumerate subdomains of a domain via crt.sh then check
python takeoverhunter.py -d example.com

# single host
python takeoverhunter.py -u sub.example.com

# with outputs
python takeoverhunter.py -l hosts.txt --json out.json --csv out.csv --report out.md

# tuning
python takeoverhunter.py -d example.com --threads 30 --timeout 10
```

## Output
- Colored console table with host, CNAME, service, confidence, fingerprint
- JSON / CSV / Markdown report

## Confidence levels
- **high** — service fingerprint found in HTTP response (strong takeover signal)
- **medium** — CNAME points to service and HTTP returns 404/403/410/502/503
- **low** — CNAME points to service but no fingerprint/error signal

## Disclaimer
Only run against targets you are authorized to test. This tool is for educational and authorized bug bounty use.

## License
MIT