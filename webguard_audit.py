#!/usr/bin/env python3
"""WebGuard Audit: passive checks for a website you own or are authorized to assess."""
from __future__ import annotations
import argparse, json, socket, ssl, urllib.error, urllib.request
from datetime import datetime, timezone
from urllib.parse import urlparse

SECURITY_HEADERS = {
 "strict-transport-security": ("HSTS", "Enforce HTTPS for future visits (only after HTTPS is configured)."),
 "content-security-policy": ("CSP", "Define trusted content sources to reduce injection impact."),
 "x-content-type-options": ("MIME sniffing protection", "Set X-Content-Type-Options: nosniff."),
 "x-frame-options": ("Clickjacking protection", "Set DENY or SAMEORIGIN, or use frame-ancestors in CSP."),
 "referrer-policy": ("Referrer policy", "Set a policy such as strict-origin-when-cross-origin."),
 "permissions-policy": ("Permissions policy", "Restrict browser features your site does not need."),
}
def normalize_target(value):
    value=value.strip()
    if "://" not in value: value="https://"+value
    parsed=urlparse(value)
    if parsed.scheme not in ("http","https") or not parsed.hostname:
        raise ValueError("Provide a valid http(s) URL or domain.")
    if parsed.username or parsed.password: raise ValueError("Credentials in URLs are not accepted.")
    return value, parsed

def audit(target, timeout=8):
    url, parsed=normalize_target(target); host=parsed.hostname
    result={"target":url,"checked_at":datetime.now(timezone.utc).isoformat(),"dns":[],"https":{},
            "headers":[],"notes":["Passive checks only. No port scanning, fuzzing or exploitation."]}
    try:
        result["dns"]=sorted({item[4][0] for item in socket.getaddrinfo(host,None)})
    except socket.gaierror as exc: result["dns_error"]=str(exc)
    if parsed.scheme=="https":
        try:
            ctx=ssl.create_default_context()
            with socket.create_connection((host,parsed.port or 443),timeout=timeout) as raw:
                with ctx.wrap_socket(raw,server_hostname=host) as tls:
                    cert=tls.getpeercert()
                    result["https"]={"tls_version":tls.version(),"cipher":tls.cipher()[0] if tls.cipher() else None,
                                     "certificate_subject":dict(x[0] for x in cert.get("subject",[])),
                                     "certificate_expires":cert.get("notAfter")}
        except (OSError,ssl.SSLError) as exc: result["https"]={"error":str(exc)}
    else:
        result["https"]={"status":"not_checked","recommendation":"Use HTTPS and redirect HTTP to HTTPS."}
    request=urllib.request.Request(url,headers={"User-Agent":"WebGuard-Audit/1.0 (passive security header review)"},method="GET")
    try:
        with urllib.request.urlopen(request,timeout=timeout) as response:
            headers={k.lower():v for k,v in response.headers.items()}
            result["http"]={"status":response.status,"final_url":response.geturl()}
            for key,(name,advice) in SECURITY_HEADERS.items():
                result["headers"].append({"header":name,"present":key in headers,
                    "value":headers.get(key,""),"recommendation":"" if key in headers else advice})
    except (urllib.error.URLError,TimeoutError,OSError) as exc:
        result["http_error"]=str(exc)
    return result

def main():
    p=argparse.ArgumentParser(description="Passive website configuration checks for authorized targets.")
    p.add_argument("target",help="Domain or URL you own or have permission to assess")
    p.add_argument("--timeout",type=int,default=8)
    p.add_argument("--output",help="Save JSON report to this file")
    a=p.parse_args()
    if not 2 <= a.timeout <= 30: p.error("--timeout must be between 2 and 30 seconds")
    try: report=audit(a.target,a.timeout)
    except ValueError as exc: p.error(str(exc))
    text=json.dumps(report,indent=2,ensure_ascii=False)
    if a.output:
        with open(a.output,"w",encoding="utf-8") as f: f.write(text+"\n")
    print(text)
if __name__=="__main__": main()
