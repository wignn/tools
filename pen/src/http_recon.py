from __future__ import annotations

import asyncio
import re
from datetime import datetime, timezone

import aiohttp


TECH_HEADERS = {
    "x-powered-by": "framework",
    "server": "server",
    "x-aspnet-version": "asp.net",
    "x-runtime": "runtime",
    "x-generator": "generator",
    "x-drupal-cache": "drupal",
    "x-varnish": "varnish",
    "x-cache": "cache_layer",
    "cf-ray": "cloudflare",
    "x-amz-cf-id": "aws_cloudfront",
    "x-vercel-id": "vercel",
    "fly-request-id": "fly.io",
    "x-render-origin-server": "render",
}

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "x-xss-protection",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
    "cross-origin-embedder-policy",
]

TECH_PATTERNS = [
    (re.compile(r"wp-content|wordpress", re.I), "WordPress"),
    (re.compile(r"joomla", re.I), "Joomla"),
    (re.compile(r"drupal", re.I), "Drupal"),
    (re.compile(r"next\.js|__next", re.I), "Next.js"),
    (re.compile(r"nuxt|__nuxt", re.I), "Nuxt.js"),
    (re.compile(r"react", re.I), "React"),
    (re.compile(r"angular", re.I), "Angular"),
    (re.compile(r"vue\.js|vue@", re.I), "Vue.js"),
    (re.compile(r"laravel", re.I), "Laravel"),
    (re.compile(r"django", re.I), "Django"),
    (re.compile(r"rails|ruby on rails", re.I), "Ruby on Rails"),
    (re.compile(r"express", re.I), "Express.js"),
    (re.compile(r"jquery", re.I), "jQuery"),
    (re.compile(r"bootstrap", re.I), "Bootstrap"),
    (re.compile(r"tailwindcss|tailwind", re.I), "Tailwind CSS"),
    (re.compile(r"cloudflare", re.I), "Cloudflare"),
]


def _extract_title(body: str) -> str:
    m = re.search(r"<title[^>]*>([^<]+)</title>", body, re.I)
    return m.group(1).strip() if m else ""


def _detect_tech(headers: dict[str, str], body: str) -> list[str]:
    found = set()

    for hdr, label in TECH_HEADERS.items():
        val = headers.get(hdr, "")
        if val:
            found.add(f"{label}: {val}")

    for pat, name in TECH_PATTERNS:
        if pat.search(body):
            found.add(name)

    return sorted(found)


def _check_security_headers(headers: dict[str, str]) -> dict[str, dict]:
    results = {}
    for hdr in SECURITY_HEADERS:
        val = headers.get(hdr)
        results[hdr] = {
            "present": val is not None,
            "value": val or "",
        }
    return results


def _extract_cookies(resp_headers: dict) -> list[dict]:
    cookies = []
    raw = resp_headers.getall("set-cookie", [])
    for c in raw:
        low = c.lower()
        cookies.append({
            "raw": c.split(";")[0],
            "secure": "secure" in low,
            "httponly": "httponly" in low,
            "samesite": "samesite" in low,
        })
    return cookies


async def http_recon(url: str, follow_redirects: bool = True) -> dict:
    timeout = aiohttp.ClientTimeout(total=15)
    redirects: list[dict] = []

    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(
                url,
                allow_redirects=follow_redirects,
                ssl=False,
                max_redirects=10,
            ) as resp:
                status = resp.status
                headers = {k.lower(): v for k, v in resp.headers.items()}
                body = await resp.text(errors="replace")

                for h in resp.history:
                    redirects.append({
                        "url": str(h.url),
                        "status": h.status,
                    })

                cookies = _extract_cookies(resp.headers)
                final_url = str(resp.url)

    except aiohttp.ClientError as e:
        return {
            "url": url,
            "scan_time": datetime.now(timezone.utc).isoformat(),
            "error": str(e),
        }
    except asyncio.TimeoutError:
        return {
            "url": url,
            "scan_time": datetime.now(timezone.utc).isoformat(),
            "error": "connection timeout",
        }

    title = _extract_title(body)
    tech = _detect_tech(headers, body)
    sec = _check_security_headers(headers)

    missing = [h for h, v in sec.items() if not v["present"]]
    present = [h for h, v in sec.items() if v["present"]]

    return {
        "url": url,
        "final_url": final_url,
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "status": status,
        "title": title,
        "server": headers.get("server", ""),
        "content_type": headers.get("content-type", ""),
        "content_length": len(body),
        "redirects": redirects,
        "technologies": tech,
        "security_headers": {
            "present": present,
            "missing": missing,
            "details": sec,
        },
        "cookies": cookies,
    }
