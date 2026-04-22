from __future__ import annotations

import aiohttp

from src.vuln import Finding

ORIGINS = [
    "https://evil.com",
    "null",
    "https://subdomain.evil.com",
]


async def scan_cors(session, url, concurrency=10):
    findings = []

    for origin in ORIGINS:
        headers = {"Origin": origin}
        try:
            async with session.get(url, headers=headers, ssl=False) as resp:
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "")

                if acao == "*":
                    findings.append(Finding(
                        vuln_type="cors-wildcard", severity="medium", url=url,
                        payload=f"Origin: {origin}", evidence=f"ACAO: {acao}",
                        description="CORS wildcard allows any origin",
                    ))
                elif acao == origin or acao == "null":
                    sev = "high" if acac.lower() == "true" else "medium"
                    findings.append(Finding(
                        vuln_type="cors-reflection", severity=sev, url=url,
                        payload=f"Origin: {origin}",
                        evidence=f"ACAO: {acao}, ACAC: {acac}",
                        description="CORS reflects arbitrary origin"
                        + (" with credentials" if acac.lower() == "true" else ""),
                    ))
                    break
        except (aiohttp.ClientError, Exception):
            continue

    return findings
