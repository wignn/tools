from __future__ import annotations

import asyncio
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import aiohttp

from src.vuln import Finding
from src.util.wordlists import XSS_PAYLOADS

REFLECTION_MARKERS = [
    re.compile(r"<script[^>]*>alert\(1\)</script>", re.I),
    re.compile(r"onerror\s*=\s*alert\(1\)", re.I),
    re.compile(r"onload\s*=\s*alert\(1\)", re.I),
    re.compile(r"onfocus\s*=\s*alert\(1\)", re.I),
    re.compile(r"ontoggle\s*=\s*alert\(1\)", re.I),
    re.compile(r"onstart\s*=\s*alert\(1\)", re.I),
    re.compile(r"<svg\s+onload", re.I),
    re.compile(r"<img\s+src\s*=\s*x\s+onerror", re.I),
    re.compile(r"<iframe\s+src\s*=\s*javascript:", re.I),
    re.compile(r"javascript\s*:\s*alert\(1\)", re.I),
]

SSTI_MARKERS = {
    "{{7*7}}": "49",
    "${7*7}": "49",
    "#{7*7}": "49",
}

DOM_SINKS = [
    re.compile(r"document\.write\s*\(", re.I),
    re.compile(r"\.innerHTML\s*=", re.I),
    re.compile(r"\.outerHTML\s*=", re.I),
    re.compile(r"eval\s*\(", re.I),
    re.compile(r"setTimeout\s*\(\s*[\"']", re.I),
    re.compile(r"setInterval\s*\(\s*[\"']", re.I),
    re.compile(r"location\s*=", re.I),
    re.compile(r"location\.href\s*=", re.I),
    re.compile(r"window\.open\s*\(", re.I),
]

DOM_SOURCES = [
    re.compile(r"location\.hash", re.I),
    re.compile(r"location\.search", re.I),
    re.compile(r"document\.referrer", re.I),
    re.compile(r"document\.URL", re.I),
    re.compile(r"window\.name", re.I),
    re.compile(r"document\.cookie", re.I),
]


def _inject_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _extract_params(url: str) -> dict[str, list[str]]:
    parsed = urlparse(url)
    return parse_qs(parsed.query, keep_blank_values=True)


async def _check_reflected(
    session: aiohttp.ClientSession,
    url: str,
    param: str,
    sem: asyncio.Semaphore,
) -> list[Finding]:
    findings = []
    for payload in XSS_PAYLOADS[:12]:
        injected = _inject_param(url, param, payload)
        async with sem:
            try:
                async with session.get(injected, ssl=False) as resp:
                    body = await resp.text(errors="replace")

                    if payload in body:
                        for marker in REFLECTION_MARKERS:
                            if marker.search(body):
                                findings.append(Finding(
                                    vuln_type="xss-reflected",
                                    severity="high",
                                    url=injected,
                                    parameter=param,
                                    payload=payload,
                                    evidence="payload reflected unescaped in response",
                                    description="Reflected XSS — unfiltered user input in HTML context",
                                ))
                                return findings

                        findings.append(Finding(
                            vuln_type="xss-reflected-partial",
                            severity="medium",
                            url=injected,
                            parameter=param,
                            payload=payload,
                            evidence="payload reflected but may be partially filtered",
                            description="Payload reflected in response, manual verification needed",
                        ))
                        return findings
            except (aiohttp.ClientError, asyncio.TimeoutError):
                continue
    return findings


async def _check_ssti(
    session: aiohttp.ClientSession,
    url: str,
    param: str,
    sem: asyncio.Semaphore,
) -> list[Finding]:
    findings = []
    for payload, expected in SSTI_MARKERS.items():
        injected = _inject_param(url, param, payload)
        async with sem:
            try:
                async with session.get(injected, ssl=False) as resp:
                    body = await resp.text(errors="replace")
                    if expected in body and payload not in body:
                        findings.append(Finding(
                            vuln_type="ssti",
                            severity="critical",
                            url=injected,
                            parameter=param,
                            payload=payload,
                            evidence=f"template expression evaluated to {expected}",
                            description="Server-Side Template Injection detected",
                        ))
                        return findings
            except (aiohttp.ClientError, asyncio.TimeoutError):
                continue
    return findings


async def _check_dom_xss(
    session: aiohttp.ClientSession,
    url: str,
    sem: asyncio.Semaphore,
) -> list[Finding]:
    findings = []
    async with sem:
        try:
            async with session.get(url, ssl=False) as resp:
                body = await resp.text(errors="replace")

                has_source = any(s.search(body) for s in DOM_SOURCES)
                has_sink = any(s.search(body) for s in DOM_SINKS)

                if has_source and has_sink:
                    findings.append(Finding(
                        vuln_type="xss-dom-potential",
                        severity="medium",
                        url=url,
                        parameter="",
                        payload="",
                        evidence="DOM source + sink pattern detected in JavaScript",
                        description="Potential DOM-based XSS — user-controlled source flows into dangerous sink",
                    ))
        except (aiohttp.ClientError, asyncio.TimeoutError):
            pass
    return findings


async def scan_xss(
    session: aiohttp.ClientSession,
    url: str,
    concurrency: int = 10,
) -> list[Finding]:
    params = _extract_params(url)
    sem = asyncio.Semaphore(concurrency)
    all_findings: list[Finding] = []

    dom_findings = await _check_dom_xss(session, url, sem)
    all_findings.extend(dom_findings)

    for param in params:
        reflected = await _check_reflected(session, url, param, sem)
        all_findings.extend(reflected)

        ssti = await _check_ssti(session, url, param, sem)
        all_findings.extend(ssti)

    return all_findings
