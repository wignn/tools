from __future__ import annotations

import asyncio
import re

from src.net import read_banner_raw, send_and_read

SERVICE_MAP: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios",
    143: "imap", 443: "https", 445: "smb", 465: "smtps", 587: "submission",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle", 1723: "pptp",
    2049: "nfs", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
    5672: "amqp", 5900: "vnc", 6379: "redis", 6443: "k8s-api",
    8080: "http-proxy", 8443: "https-alt", 9090: "prometheus",
    9200: "elasticsearch", 11211: "memcached", 27017: "mongodb",
}

HTTP_PROBE = (
    b"HEAD / HTTP/1.1\r\n"
    b"Host: target\r\n"
    b"Connection: close\r\n"
    b"\r\n"
)

SMTP_BANNER_RE = re.compile(r"^2\d{2}[ -]", re.MULTILINE)
SSH_BANNER_RE = re.compile(r"^SSH-\d")
FTP_BANNER_RE = re.compile(r"^2\d{2}[ -]")


def _identify_service(port: int, banner: str) -> str:
    low = banner.lower()

    if SSH_BANNER_RE.match(banner):
        return "ssh"
    if FTP_BANNER_RE.match(banner) and ("ftp" in low or "filezilla" in low or "vsftpd" in low):
        return "ftp"
    if SMTP_BANNER_RE.match(banner) and ("smtp" in low or "mail" in low or "postfix" in low):
        return "smtp"
    if "mysql" in low or "mariadb" in low:
        return "mysql"
    if "postgresql" in low:
        return "postgresql"
    if "redis" in low:
        return "redis"
    if "mongodb" in low or "mongod" in low:
        return "mongodb"
    if "http" in low or "html" in low or "server:" in low:
        return "http"
    if "imap" in low:
        return "imap"
    if "pop3" in low or "+ok" in low:
        return "pop3"
    if "vnc" in low or banner.startswith("RFB"):
        return "vnc"

    return SERVICE_MAP.get(port, "unknown")


async def _grab_single(ip: str, port: int, timeout: float) -> dict:
    banner = await read_banner_raw(ip, port, timeout)

    if not banner and port in (80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9090):
        banner = await send_and_read(ip, port, HTTP_PROBE, timeout)

    service = _identify_service(port, banner)

    return {
        "service": service,
        "banner": banner[:512] if banner else "",
    }


async def grab_banners(
    ip: str,
    ports: list[int],
    timeout: float,
) -> dict[int, dict]:
    sem = asyncio.Semaphore(20)
    results: dict[int, dict] = {}

    async def _grab(port: int) -> None:
        async with sem:
            results[port] = await _grab_single(ip, port, timeout)

    await asyncio.gather(*[_grab(p) for p in ports])
    return results
