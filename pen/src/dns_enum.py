from __future__ import annotations

import asyncio
from pathlib import Path

import dns.asyncresolver
import dns.resolver


DEFAULT_WORDLIST = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "mx",
    "ns1", "ns2", "ns3", "dns", "dns1", "dns2",
    "api", "app", "dev", "staging", "stage", "test", "qa", "uat",
    "beta", "demo", "sandbox", "preview",
    "admin", "panel", "dashboard", "portal", "console", "manage",
    "login", "auth", "sso", "accounts", "id",
    "static", "cdn", "assets", "media", "img", "images", "files",
    "docs", "help", "support", "wiki", "blog", "status",
    "shop", "store", "pay", "billing",
    "git", "gitlab", "ci", "jenkins",
    "monitor", "grafana", "prometheus", "kibana", "logs",
    "db", "mysql", "postgres", "mongo", "redis", "cache",
    "vpn", "proxy", "gateway", "lb",
    "m", "mobile", "v1", "v2", "internal", "secure",
    "old", "legacy", "backup", "tmp",
    "s3", "storage", "archive",
    "mx1", "mx2", "relay",
    "www1", "www2", "web",
]


def _load_wordlist(path: Path | None) -> list[str]:
    if path and path.is_file():
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        return [w.strip().lower() for w in lines if w.strip() and not w.startswith("#")]
    return list(DEFAULT_WORDLIST)


async def _resolve(fqdn: str, resolver: dns.asyncresolver.Resolver) -> dict | None:
    try:
        answers = await resolver.resolve(fqdn, "A")
        ips = [rdata.address for rdata in answers]
        return {"subdomain": fqdn, "ips": ips}
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return None
    except dns.resolver.LifetimeTimeout:
        return None
    except Exception:
        return None


async def enumerate_subdomains(
    domain: str,
    wordlist_path: Path | None = None,
    concurrency: int = 50,
) -> list[dict]:
    words = _load_wordlist(wordlist_path)
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 3.0
    resolver.timeout = 3.0

    sem = asyncio.Semaphore(concurrency)
    results: list[dict] = []
    total = len(words)

    async def _check(word: str) -> None:
        fqdn = f"{word}.{domain}"
        async with sem:
            result = await _resolve(fqdn, resolver)
            if result:
                results.append(result)
                ips = ", ".join(result["ips"])
                print(f"  \x1b[32m●\x1b[0m \x1b[1m{fqdn}\x1b[0m → {ips}")

    await asyncio.gather(*[asyncio.create_task(_check(w)) for w in words])

    print(f"\n  \x1b[90m{total} subdomains checked — {len(results)} found\x1b[0m\n")
    return sorted(results, key=lambda r: r["subdomain"])
