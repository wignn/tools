from __future__ import annotations

import asyncio
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import aiohttp

from src.vuln import Finding
from src.util.wordlists import SQLI_PAYLOADS

SQL_ERRORS = [
    r"you have an error in your sql syntax",
    r"warning.*mysql",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"microsoft ole db provider for sql server",
    r"pg_query\(\).*error",
    r"pg_exec\(\).*error",
    r"supplied argument is not a valid postgresql",
    r"unterminated quoted string at or near",
    r"syntax error at or near",
    r"ora-\d{5}",
    r"oracle.*driver.*error",
    r"sql command not properly ended",
    r"sqlite3\.operationalerror",
    r"near \".*?\": syntax error",
    r"unrecognized token",
    r"jdbc\.sqlserver",
    r"com\.mysql\.jdbc",
    r"org\.postgresql\.util",
    r"sqlstate\[",
    r"pdo.*exception",
    r"db2 sql error",
    r"dynamic sql error",
]

COMPILED_ERRORS = [re.compile(p, re.I) for p in SQL_ERRORS]

TIME_PAYLOADS = [
    ("' AND SLEEP(5)--", 5),
    ("' OR SLEEP(5)--", 5),
    ("1; WAITFOR DELAY '0:0:5'--", 5),
    ("1; SELECT pg_sleep(5)--", 5),
    ("1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--", 5),
]

BOOLEAN_PAIRS = [
    ("' AND '1'='1", "' AND '1'='2"),
    ("' OR '1'='1", "' OR '1'='2"),
    ("1 AND 1=1", "1 AND 1=2"),
]


def _extract_params(url: str) -> dict[str, list[str]]:
    parsed = urlparse(url)
    return parse_qs(parsed.query, keep_blank_values=True)


def _inject_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


async def _check_error_based(
    session: aiohttp.ClientSession,
    url: str,
    param: str,
    sem: asyncio.Semaphore,
) -> list[Finding]:
    findings = []
    for payload in SQLI_PAYLOADS[:12]:
        injected = _inject_param(url, param, payload)
        async with sem:
            try:
                async with session.get(injected, ssl=False) as resp:
                    body = await resp.text(errors="replace")
                    body_lower = body.lower()
                    for pattern in COMPILED_ERRORS:
                        if pattern.search(body_lower):
                            findings.append(Finding(
                                vuln_type="sqli-error",
                                severity="high",
                                url=injected,
                                parameter=param,
                                payload=payload,
                                evidence=pattern.pattern[:80],
                                description="SQL error message leaked in response",
                            ))
                            return findings
            except (aiohttp.ClientError, asyncio.TimeoutError):
                continue
    return findings


async def _check_boolean_based(
    session: aiohttp.ClientSession,
    url: str,
    param: str,
    sem: asyncio.Semaphore,
) -> list[Finding]:
    findings = []
    for true_payload, false_payload in BOOLEAN_PAIRS:
        true_url = _inject_param(url, param, true_payload)
        false_url = _inject_param(url, param, false_payload)
        async with sem:
            try:
                async with session.get(true_url, ssl=False) as r1:
                    body_true = await r1.text(errors="replace")
                    status_true = r1.status
                async with session.get(false_url, ssl=False) as r2:
                    body_false = await r2.text(errors="replace")
                    status_false = r2.status

                len_diff = abs(len(body_true) - len(body_false))
                if status_true == status_false and len_diff > 50:
                    findings.append(Finding(
                        vuln_type="sqli-boolean",
                        severity="high",
                        url=url,
                        parameter=param,
                        payload=f"T: {true_payload} | F: {false_payload}",
                        evidence=f"response length diff: {len_diff} bytes",
                        description="Boolean-based blind SQL injection detected",
                    ))
                    return findings
            except (aiohttp.ClientError, asyncio.TimeoutError):
                continue
    return findings


async def _check_time_based(
    session: aiohttp.ClientSession,
    url: str,
    param: str,
    sem: asyncio.Semaphore,
) -> list[Finding]:
    findings = []

    async with sem:
        try:
            baseline_url = _inject_param(url, param, "1")
            import time
            t0 = time.monotonic()
            async with session.get(baseline_url, ssl=False) as _:
                pass
            baseline_time = time.monotonic() - t0
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return findings

    for payload, delay in TIME_PAYLOADS[:2]:
        injected = _inject_param(url, param, payload)
        async with sem:
            try:
                import time
                t0 = time.monotonic()
                async with session.get(injected, ssl=False) as _:
                    pass
                elapsed = time.monotonic() - t0

                if elapsed >= (baseline_time + delay - 1):
                    findings.append(Finding(
                        vuln_type="sqli-time",
                        severity="critical",
                        url=injected,
                        parameter=param,
                        payload=payload,
                        evidence=f"response delayed {elapsed:.1f}s (baseline {baseline_time:.1f}s)",
                        description="Time-based blind SQL injection detected",
                    ))
                    return findings
            except asyncio.TimeoutError:
                findings.append(Finding(
                    vuln_type="sqli-time",
                    severity="medium",
                    url=injected,
                    parameter=param,
                    payload=payload,
                    evidence="request timed out (possible time-based injection)",
                    description="Possible time-based blind SQL injection",
                ))
                return findings
            except aiohttp.ClientError:
                continue
    return findings


async def scan_sqli(
    session: aiohttp.ClientSession,
    url: str,
    concurrency: int = 10,
) -> list[Finding]:
    params = _extract_params(url)
    if not params:
        return []

    sem = asyncio.Semaphore(concurrency)
    all_findings: list[Finding] = []

    for param in params:
        error_findings = await _check_error_based(session, url, param, sem)
        all_findings.extend(error_findings)

        if not error_findings:
            bool_findings = await _check_boolean_based(session, url, param, sem)
            all_findings.extend(bool_findings)

        if not error_findings:
            time_findings = await _check_time_based(session, url, param, sem)
            all_findings.extend(time_findings)

    return all_findings
