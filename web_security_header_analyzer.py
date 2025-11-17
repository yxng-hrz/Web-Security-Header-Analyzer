#!/usr/bin/env python3
"""
Web Security Header Analyzer

Small CLI tool that checks common web security headers for a given URL and
computes a simple score + grade.

Usage examples:
    python web_security_header_analyzer.py https://example.com
    python web_security_header_analyzer.py example.com --format markdown --output report.md
"""

import argparse
import sys
from typing import List, Dict, Any
from urllib.parse import urlparse

import requests


def normalize_url(url: str) -> str:
    """Ensure the URL has a scheme (default to https://)."""
    parsed = urlparse(url)
    if not parsed.scheme:
        return "https://" + url
    return url


def grade(score: int, max_score: int) -> str:
    """Compute a letter grade from the numeric score."""
    if max_score == 0:
        return "N/A"
    pct = (score / max_score) * 100
    if pct >= 90:
        return "A"
    elif pct >= 80:
        return "B"
    elif pct >= 65:
        return "C"
    elif pct >= 50:
        return "D"
    else:
        return "E"


def analyze_headers(url: str) -> Dict[str, Any]:
    """Fetch the URL and evaluate common web security headers."""
    normalized_url = normalize_url(url)
    try:
        resp = requests.get(normalized_url, timeout=10, allow_redirects=True)
    except requests.RequestException as e:
        raise SystemExit(f"[!] Failed to fetch {normalized_url}: {e}")

    headers = {k.lower(): v for k, v in resp.headers.items()}
    final_url = resp.url
    final_scheme = urlparse(final_url).scheme

    findings: List[Dict[str, Any]] = []
    score = 0
    max_score = 0

    def add_check(
        id_: str,
        title: str,
        ok: bool,
        weight: int,
        severity: str,
        details_ok: str,
        details_fail: str,
    ) -> None:
        nonlocal score, max_score
        max_score += weight
        if ok:
            score += weight
            details = details_ok
        else:
            details = details_fail
        findings.append(
            {
                "id": id_,
                "title": title,
                "ok": ok,
                "weight": weight,
                "severity": severity,
                "details": details,
            }
        )

    # 1. HTTPS enforcement
    is_https = final_scheme == "https"
    add_check(
        "WEB-HTTPS-01",
        "HTTPS enforced",
        is_https,
        weight=20,
        severity="HIGH",
        details_ok=f"Final URL uses HTTPS: {final_url}",
        details_fail=f"Final URL does not use HTTPS (scheme={final_scheme}).",
    )

    # 2. HTTP Strict Transport Security (HSTS)
    hsts = headers.get("strict-transport-security")
    has_hsts = bool(hsts) and is_https
    add_check(
        "WEB-HSTS-01",
        "HTTP Strict Transport Security (HSTS)",
        has_hsts,
        weight=15,
        severity="HIGH",
        details_ok=f"HSTS is configured: {hsts}",
        details_fail=(
            "HSTS header is missing. Browsers may access the site over plain HTTP "
            "after redirects."
        ),
    )

    # 3. Content-Security-Policy (CSP)
    csp = headers.get("content-security-policy")
    has_csp = bool(csp)
    add_check(
        "WEB-CSP-01",
        "Content Security Policy (CSP)",
        has_csp,
        weight=20,
        severity="HIGH",
        details_ok=f"CSP header present: {csp}",
        details_fail=(
            "CSP header is missing. This increases the risk of XSS and content injection."
        ),
    )

    # 4. X-Frame-Options
    xfo = headers.get("x-frame-options")
    has_xfo = bool(xfo)
    add_check(
        "WEB-XFO-01",
        "X-Frame-Options (clickjacking protection)",
        has_xfo,
        weight=10,
        severity="MEDIUM",
        details_ok=f"X-Frame-Options configured: {xfo}",
        details_fail="X-Frame-Options header is missing. The site may be vulnerable to clickjacking.",
    )

    # 5. X-Content-Type-Options
    xcto = headers.get("x-content-type-options")
    has_xcto = xcto is not None and xcto.lower() == "nosniff"
    add_check(
        "WEB-XCTO-01",
        "X-Content-Type-Options (MIME sniffing protection)",
        has_xcto,
        weight=10,
        severity="MEDIUM",
        details_ok="X-Content-Type-Options correctly set to 'nosniff'.",
        details_fail="X-Content-Type-Options is missing or not set to 'nosniff'.",
    )

    # 6. Referrer-Policy
    refpol = headers.get("referrer-policy")
    has_refpol = bool(refpol)
    add_check(
        "WEB-REF-01",
        "Referrer-Policy (information leakage)",
        has_refpol,
        weight=10,
        severity="LOW",
        details_ok=f"Referrer-Policy configured: {refpol}",
        details_fail="Referrer-Policy header is missing.",
    )

    # 7. Cookie security flags
    set_cookie = headers.get("set-cookie", "")
    has_cookies = bool(set_cookie)
    cookies_secure_ok = True
    cookies_httponly_ok = True

    if has_cookies:
        cookies_lower = set_cookie.lower()
        cookies_secure_ok = "secure" in cookies_lower
        cookies_httponly_ok = "httponly" in cookies_lower

    cookies_ok = (not has_cookies) or (cookies_secure_ok and cookies_httponly_ok)
    add_check(
        "WEB-CK-01",
        "Cookie security flags (Secure & HttpOnly)",
        cookies_ok,
        weight=15,
        severity="HIGH",
        details_ok=(
            "All cookies appear to use Secure and HttpOnly flags "
            "(or no cookies are set)."
        ),
        details_fail="Some cookies may be missing Secure and/or HttpOnly flags.",
    )

    return {
        "requested_url": url,
        "final_url": final_url,
        "https": is_https,
        "score": score,
        "max_score": max_score,
        "grade": grade(score, max_score),
        "findings": findings,
    }


def render_text(result: Dict[str, Any]) -> str:
    """Render a human-readable text report."""
    lines: List[str] = []
    lines.append(f"Web Security Header Analysis for: {result['requested_url']}")
    lines.append(f"Final URL: {result['final_url']}")
    lines.append(f"HTTPS: {'YES' if result['https'] else 'NO'}")
    lines.append(
        f"Score: {result['score']} / {result['max_score']} (grade {result['grade']})"
    )
    lines.append("")
    lines.append("Findings:")
    for finding in result["findings"]:
        status = "OK  " if finding["ok"] else "FAIL"
        lines.append(
            f"  [{status}] {finding['id']} - {finding['title']} "
            f"({finding['severity']})"
        )
        lines.append(f"      {finding['details']}")
    return "\n".join(lines)


def render_markdown(result: Dict[str, Any]) -> str:
    """Render a Markdown report."""
    lines: List[str] = []
    lines.append("# Web Security Header Analysis")
    lines.append("")
    lines.append(f"- **Requested URL:** `{result['requested_url']}`")
    lines.append(f"- **Final URL:** `{result['final_url']}`")
    lines.append(f"- **HTTPS:** {'✅ Yes' if result['https'] else '❌ No'}")
    lines.append(f"- **Score:** **{result['score']} / {result['max_score']}**")
    lines.append(f"- **Grade:** **{result['grade']}**")
    lines.append("")
    lines.append("## Findings")
    lines.append("")
    for finding in result["findings"]:
        emoji = "✅" if finding["ok"] else "❌"
        lines.append(
            f"- {emoji} **{finding['id']} – {finding['title']}**"
        )
        lines.append(f"  - Severity: `{finding['severity']}`")
        lines.append(f"  - Details: {finding['details']}")
    return "\n".join(lines)


def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Analyze web security headers for a given URL "
            "(HTTPS, HSTS, CSP, etc.)."
        )
    )
    parser.add_argument(
        "url",
        help=(
            "Target URL to analyze (e.g. https://example.com). "
            "Scheme will default to https:// if omitted."
        ),
    )
    parser.add_argument(
        "--format",
        choices=["text", "markdown"],
        default="text",
        help="Output format (default: text).",
    )
    parser.add_argument(
        "--output",
        help="Optional file path to write the report. If omitted, prints to stdout.",
    )
    return parser.parse_args(argv)


def main(argv: List[str]) -> None:
    args = parse_args(argv)
    result = analyze_headers(args.url)

    if args.format == "markdown":
        content = render_markdown(result)
    else:
        content = render_text(result)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(content)
            print(f"[+] Report written to {args.output}")
        except OSError as e:
            print(f"[!] Failed to write report to {args.output}: {e}")
    else:
        print(content)


if __name__ == "__main__":
    main(sys.argv[1:])
