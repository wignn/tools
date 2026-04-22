from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

import aiohttp

from src.vuln.sqli import scan_sqli
from src.vuln.xss import scan_xss
from src.vuln.lfi import scan_lfi
from src.vuln.cmdi import scan_cmdi
from src.vuln.cors import scan_cors
from src.vuln.open_redirect import scan_open_redirect


@dataclass
class Finding:
    vuln_type: str
    severity: str
    url: str
    parameter: str = ""
    payload: str = ""
    evidence: str = ""
    description: str = ""


@dataclass
class VulnReport:
    target: str
    scan_time: str = ""
    findings: list[Finding] = field(default_factory=list)
    modules_run: list[str] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "scan_time": self.scan_time,
            "total_findings": len(self.findings),
            "by_severity": self._severity_counts(),
            "modules_run": self.modules_run,
            "findings": [
                {
                    "vuln_type": f.vuln_type,
                    "severity": f.severity,
                    "url": f.url,
                    "parameter": f.parameter,
                    "payload": f.payload,
                    "evidence": f.evidence[:200],
                    "description": f.description,
                }
                for f in self.findings
            ],
            "error": self.error,
        }

    def _severity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts


ALL_MODULES = {
    "sqli": scan_sqli,
    "xss": scan_xss,
    "lfi": scan_lfi,
    "cmdi": scan_cmdi,
    "cors": scan_cors,
    "redirect": scan_open_redirect,
}


async def run_vuln_scan(
    url: str,
    modules: list[str] | None = None,
    concurrency: int = 10,
    timeout: float = 10.0,
) -> VulnReport:
    chosen = modules or list(ALL_MODULES.keys())
    report = VulnReport(
        target=url,
        scan_time=datetime.now(timezone.utc).isoformat(),
    )

    tcp_timeout = aiohttp.ClientTimeout(total=timeout)
    try:
        async with aiohttp.ClientSession(timeout=tcp_timeout) as session:
            for mod_name in chosen:
                scanner = ALL_MODULES.get(mod_name)
                if not scanner:
                    continue
                report.modules_run.append(mod_name)
                print(f"  \x1b[90m⏳ Running {mod_name}...\x1b[0m")
                findings = await scanner(session, url, concurrency)
                for f in findings:
                    report.findings.append(f)
                    sev_color = {
                        "critical": "\x1b[1;41;37m",
                        "high": "\x1b[1;31m",
                        "medium": "\x1b[1;33m",
                        "low": "\x1b[90m",
                        "info": "\x1b[36m",
                    }.get(f.severity, "\x1b[0m")
                    print(
                        f"  {sev_color} {f.severity.upper():<8}\x1b[0m "
                        f"\x1b[1m{f.vuln_type}\x1b[0m"
                        f"  \x1b[90m{f.parameter}\x1b[0m"
                    )
    except aiohttp.ClientError as e:
        report.error = str(e)
    except Exception as e:
        report.error = str(e)

    print()
    return report
