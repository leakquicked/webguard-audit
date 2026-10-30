# WebGuard Audit

A small Python CLI for **passive website configuration reviews** on domains you own or are explicitly authorized to assess.

## Checks
- DNS address resolution using the operating system resolver.
- HTTPS/TLS connection, negotiated TLS version, cipher and certificate expiry field.
- HTTP response status and six common security headers.
- JSON report output.

## Quick start
Requires Python 3.10+; no third-party packages.

```bash
python webguard_audit.py example.com
python webguard_audit.py https://your-domain.example --output audit.json
python webguard_audit.py http://your-domain.example --timeout 12
python -m unittest discover -s tests -v
```

## Important limitations
- The script makes a DNS lookup, one HTTPS certificate connection (for HTTPS targets), and one HTTP GET request to the supplied URL. It does not crawl links or scan ports.
- DNS answers depend on your system resolver. Certificate details depend on the TLS library and server response.
- Redirects are followed by Python's standard library. Header results describe the final response.
- A missing header is a review finding, not proof that a site is vulnerable. Some headers may be unnecessary depending on the application.
- This is not a penetration test, compliance certification, or substitute for expert review.

## Authorization & privacy
Run only against websites you own or have permission to assess. The target receives ordinary DNS/HTTPS/HTTP requests. Do not use this tool for mass scanning or against third-party systems without authorization.

## Project
MIT License. Educational defensive-security tooling.
