# Methodology

1. **Enumeration**: Collect candidate subdomains via Certificate Transparency logs (crt.sh) or user-supplied list.
2. **DNS resolution**: Resolve each host's CNAME chain using a built-in DNS client.
3. **Service matching**: Match the CNAME suffix against known takeover-prone services.
4. **HTTP fingerprinting**: Fetch the host and search the response body for service-specific dangling-resource fingerprints.
5. **Confidence scoring**:
   - high — fingerprint present (strong takeover signal)
   - medium — CNAME points to service AND HTTP returns 404/403/410/502/503
   - low — CNAME points to service, no fingerprint/error signal
6. **Reporting**: Persist to SQLite, export JSON/CSV/Markdown/HTML.
