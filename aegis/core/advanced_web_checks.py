from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import httpx


def _with_query(url: str, updates: dict[str, str]) -> str:
    parsed = urlparse(url)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query.update(updates)
    return urlunparse(parsed._replace(query=urlencode(query)))


def run_advanced_authorized_checks(
    url: str,
    *,
    timeout: int = 10,
    include_dangerous: bool = False,
) -> list[dict]:
    findings: list[dict] = []
    with httpx.Client(timeout=timeout, follow_redirects=True, verify=False) as client:  # noqa: S501
        baseline = client.get(url)

        # Auth/session hardening checks
        set_cookie = baseline.headers.get("set-cookie", "")
        if set_cookie and ("secure" not in set_cookie.lower() or "httponly" not in set_cookie.lower()):
            findings.append(
                {
                    "title": "Session cookie missing hardened attributes",
                    "severity": "medium",
                    "category": "auth-session",
                    "description": "Set-Cookie detected without Secure and/or HttpOnly.",
                    "source": "advanced-web",
                    "reproducibility": f"GET {url} and inspect Set-Cookie",
                    "remediation": "Set Secure, HttpOnly, and SameSite on authentication cookies.",
                }
            )

        # Access control / IDOR heuristic
        idor_url = _with_query(url, {"id": "1001"})
        idor_next = _with_query(url, {"id": "1002"})
        r1 = client.get(idor_url)
        r2 = client.get(idor_next)
        if r1.status_code == 200 and r2.status_code == 200 and len(r1.text) and len(r2.text):
            findings.append(
                {
                    "title": "Potential IDOR via sequential identifier",
                    "severity": "medium",
                    "category": "access-control",
                    "description": "Sequential id parameter returned comparable successful responses.",
                    "source": "advanced-web",
                    "reproducibility": f"Compare responses for {idor_url} and {idor_next}",
                    "remediation": "Enforce server-side object authorization for each requested record.",
                }
            )

        # Business-logic sanity
        if baseline.request.method == "GET" and baseline.status_code == 200:
            trace = client.request("TRACE", url)
            if trace.status_code < 400:
                findings.append(
                    {
                        "title": "TRACE method appears enabled",
                        "severity": "low",
                        "category": "business-logic",
                        "description": "TRACE may increase attack surface and should typically be disabled.",
                        "source": "advanced-web",
                        "reproducibility": f"Send TRACE {url}",
                        "remediation": "Disable unnecessary HTTP methods in production.",
                    }
                )

        # SSRF/LFI pattern family probes (non-destructive reflection heuristics)
        ssrf_probe = _with_query(url, {"url": "http://127.0.0.1:80/"})
        ssrf_resp = client.get(ssrf_probe)
        if "127.0.0.1" in ssrf_resp.text or "localhost" in ssrf_resp.text:
            findings.append(
                {
                    "title": "Potential SSRF parameter reflection",
                    "severity": "medium",
                    "category": "ssrf",
                    "description": "User-supplied URL parameter reflected or used by backend logic.",
                    "source": "advanced-web",
                    "reproducibility": f"GET {ssrf_probe}",
                    "remediation": "Apply strict outbound allowlists and canonical URL validation.",
                }
            )

        lfi_probe = _with_query(url, {"file": "../../../../etc/passwd"})
        lfi_resp = client.get(lfi_probe)
        if "root:x:" in lfi_resp.text:
            findings.append(
                {
                    "title": "Potential LFI file disclosure signature",
                    "severity": "high",
                    "category": "lfi",
                    "description": "Response includes markers consistent with /etc/passwd disclosure.",
                    "source": "advanced-web",
                    "reproducibility": f"GET {lfi_probe}",
                    "remediation": "Disallow path traversal and map file access to fixed server-side identifiers.",
                }
            )

        # API auth/schema checks
        api_spec = client.get(url.rstrip("/") + "/openapi.json")
        if api_spec.status_code == 200 and "paths" in api_spec.text:
            findings.append(
                {
                    "title": "OpenAPI schema exposed anonymously",
                    "severity": "low",
                    "category": "api-auth-schema",
                    "description": "OpenAPI endpoint appears publicly accessible without authentication.",
                    "source": "advanced-web",
                    "reproducibility": f"GET {url.rstrip('/') + '/openapi.json'}",
                    "remediation": "Restrict schema access or sanitize non-public endpoints from public docs.",
                }
            )

        if include_dangerous:
            destructive_probe = _with_query(url, {"action": "delete", "dry_run": "false"})
            dangerous = client.get(destructive_probe)
            findings.append(
                {
                    "title": "Dangerous business-action probe executed",
                    "severity": "info",
                    "category": "dangerous-probe",
                    "description": f"Explicit dangerous flag enabled; probe status={dangerous.status_code}.",
                    "source": "advanced-web",
                    "reproducibility": f"GET {destructive_probe}",
                    "remediation": "Require strong authz and anti-automation controls for state-changing actions.",
                }
            )
    return findings
