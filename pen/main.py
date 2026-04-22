from __future__ import annotations

import argparse
import asyncio
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from src.config import load_profile
from src.port_scanner import tcp_scan
from src.banner import grab_banners
from src.http_recon import http_recon
from src.dns_enum import enumerate_subdomains
from src.vuln import run_vuln_scan, ALL_MODULES
from src.exploit.fuzzer import fuzz_directories
from src.exploit.bruteforce import brute_http_basic, brute_http_form
from src.exploit.default_creds import test_default_creds
from src.exploit.shells import generate_shell, generate_all_shells, list_shell_types
from src.exploit.payloads import encode_payload, decode_payload, encode_all
from src.reporter import (
    print_banner, print_target, print_results,
    print_saved, print_shell, print_encode_result,
)
from src.net import resolve_host


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pen",
        description="Network penetration testing toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  python main.py scan 192.168.1.1
  python main.py scan example.com --profile full
  python main.py vuln https://example.com/page?id=1
  python main.py fuzz https://example.com
  python main.py brute https://example.com/admin --mode basic
  python main.py creds https://example.com
  python main.py shell -t bash-tcp -H 10.10.14.1 -P 4444
  python main.py shell --list
  python main.py encode "alert(1)" -e base64
  python main.py decode "YWxlcnQoMSk=" -e base64
""",
    )
    sub = p.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="port scan + banner grab")
    scan.add_argument("target")
    scan.add_argument("-p", "--ports", help="ports (e.g. 80,443 or 1-1024)")
    scan.add_argument("--profile", choices=["quick", "standard", "full"], default="standard")
    scan.add_argument("--timeout", type=float)
    scan.add_argument("--concurrency", type=int)
    scan.add_argument("--no-banner", action="store_true")
    scan.add_argument("-o", "--output")

    enum = sub.add_parser("enum", help="subdomain enumeration")
    enum.add_argument("domain")
    enum.add_argument("-w", "--wordlist")
    enum.add_argument("--concurrency", type=int, default=50)
    enum.add_argument("-o", "--output")

    http = sub.add_parser("http", help="HTTP recon")
    http.add_argument("url")
    http.add_argument("--no-redirect", action="store_true")
    http.add_argument("-o", "--output")

    vuln = sub.add_parser("vuln", help="vulnerability scan (sqli, xss, lfi, cmdi, cors, redirect)")
    vuln.add_argument("url")
    vuln.add_argument("-m", "--modules", help="comma-separated modules (default: all)")
    vuln.add_argument("--concurrency", type=int, default=10)
    vuln.add_argument("--timeout", type=float, default=10.0)
    vuln.add_argument("-o", "--output")

    fuzz = sub.add_parser("fuzz", help="directory / endpoint fuzzer")
    fuzz.add_argument("url")
    fuzz.add_argument("-w", "--wordlist")
    fuzz.add_argument("-x", "--extensions", help="extensions (e.g. .php,.html,.js)")
    fuzz.add_argument("--concurrency", type=int, default=30)
    fuzz.add_argument("--timeout", type=float, default=10.0)
    fuzz.add_argument("--status", help="show only these status codes (e.g. 200,301,403)")
    fuzz.add_argument("--hide", help="hide these status codes (default: 404)")
    fuzz.add_argument("-o", "--output")

    brute = sub.add_parser("brute", help="HTTP auth brute force")
    brute.add_argument("url")
    brute.add_argument("--mode", choices=["basic", "form"], default="basic")
    brute.add_argument("-u", "--username", help="single username")
    brute.add_argument("-U", "--user-file", help="username wordlist file")
    brute.add_argument("-P", "--pass-file", help="password wordlist file")
    brute.add_argument("--user-field", default="username")
    brute.add_argument("--pass-field", default="password")
    brute.add_argument("--fail-text", default="", help="text that indicates login failure")
    brute.add_argument("--concurrency", type=int, default=10)
    brute.add_argument("-o", "--output")

    creds = sub.add_parser("creds", help="default credential testing")
    creds.add_argument("url")
    creds.add_argument("-s", "--services", help="comma-separated services to test")
    creds.add_argument("--concurrency", type=int, default=5)
    creds.add_argument("-o", "--output")

    shell = sub.add_parser("shell", help="reverse shell payload generator")
    shell.add_argument("-t", "--type", dest="shell_type", help="shell type")
    shell.add_argument("-H", "--host", dest="lhost")
    shell.add_argument("-P", "--port", dest="lport", type=int)
    shell.add_argument("-e", "--encoding", default="raw", help="raw, base64, url, powershell-base64")
    shell.add_argument("--all", action="store_true", help="generate all shell types")
    shell.add_argument("--list", action="store_true", help="list available shell types")

    enc = sub.add_parser("encode", help="payload encoding")
    enc.add_argument("data")
    enc.add_argument("-e", "--encoding", default="base64")
    enc.add_argument("--all", action="store_true")

    dec = sub.add_parser("decode", help="payload decoding")
    dec.add_argument("data")
    dec.add_argument("-e", "--encoding", default="base64")

    return p


def parse_ports(raw, profile):
    if not raw:
        return profile.ports
    ports = set()
    for part in raw.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.update(range(int(lo), int(hi) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


async def cmd_scan(args):
    profile = load_profile(args.profile)
    if args.timeout: profile.timeout = args.timeout
    if args.concurrency: profile.concurrency = args.concurrency
    ports = parse_ports(args.ports, profile)
    ip = await resolve_host(args.target)
    print_target(args.target, ip, len(ports), profile)
    open_ports = await tcp_scan(ip, ports, profile.timeout, profile.concurrency)
    banners = {}
    if open_ports and not args.no_banner:
        banners = await grab_banners(ip, open_ports, profile.timeout)
    return {
        "target": args.target, "ip": ip,
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "profile": profile.name, "ports_scanned": len(ports),
        "open_ports": [
            {"port": p, "service": banners.get(p, {}).get("service", "unknown"),
             "banner": banners.get(p, {}).get("banner", "")}
            for p in open_ports
        ],
    }


async def cmd_enum(args):
    wl = Path(args.wordlist) if args.wordlist else None
    results = await enumerate_subdomains(args.domain, wl, args.concurrency)
    return {
        "domain": args.domain,
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "subdomains_found": len(results), "results": results,
    }


async def cmd_http(args):
    return await http_recon(args.url, not args.no_redirect)


async def cmd_vuln(args):
    modules = args.modules.split(",") if args.modules else None
    report = await run_vuln_scan(args.url, modules, args.concurrency, args.timeout)
    return report.to_dict()


async def cmd_fuzz(args):
    wl = Path(args.wordlist) if args.wordlist else None
    exts = args.extensions.split(",") if args.extensions else None
    status_filter = set(int(s) for s in args.status.split(",")) if args.status else None
    hide = set(int(s) for s in args.hide.split(",")) if args.hide else {404}
    return await fuzz_directories(args.url, wl, exts, args.concurrency, args.timeout, status_filter, hide)


async def cmd_brute(args):
    users = [args.username] if args.username else None
    uf = Path(args.user_file) if args.user_file else None
    pf = Path(args.pass_file) if args.pass_file else None
    if args.mode == "basic":
        return await brute_http_basic(args.url, users, None, uf, pf, args.concurrency)
    else:
        return await brute_http_form(
            args.url, args.user_field, args.pass_field, args.fail_text,
            users, None, uf, pf, args.concurrency,
        )


async def cmd_creds(args):
    svcs = args.services.split(",") if args.services else None
    return await test_default_creds(args.url, svcs, args.concurrency)


def cmd_shell(args):
    if args.list:
        types = list_shell_types()
        print("  \x1b[1mAvailable shell types:\x1b[0m\n")
        for t in types:
            print(f"    \x1b[36m{t['type']:<20}\x1b[0m {t['name']}")
        print()
        return None

    if args.all:
        if not args.lhost or not args.lport:
            print("  \x1b[31m--all requires -H and -P\x1b[0m")
            sys.exit(1)
        shells = generate_all_shells(args.lhost, args.lport)
        for s in shells:
            print_shell(s)
        return {"host": args.lhost, "port": args.lport, "shells": shells}

    if not args.shell_type or not args.lhost or not args.lport:
        print("  \x1b[31mRequired: -t <type> -H <host> -P <port>\x1b[0m")
        print("  \x1b[90mUse --list to see available types\x1b[0m")
        sys.exit(1)

    result = generate_shell(args.shell_type, args.lhost, args.lport, args.encoding)
    if "error" in result:
        print(f"  \x1b[31m{result['error']}\x1b[0m")
        if "available" in result:
            print(f"  \x1b[90mAvailable: {', '.join(result['available'])}\x1b[0m")
        sys.exit(1)

    print_shell(result)
    return result


def cmd_encode(args):
    if args.all:
        result = encode_all(args.data)
    else:
        result = encode_payload(args.data, args.encoding)
    if "error" in result:
        print(f"  \x1b[31m{result['error']}\x1b[0m")
        sys.exit(1)
    print_encode_result(result)
    return result


def cmd_decode(args):
    result = decode_payload(args.data, args.encoding)
    if "error" in result:
        print(f"  \x1b[31m{result['error']}\x1b[0m")
        sys.exit(1)
    print_encode_result(result)
    return result


ASYNC_COMMANDS = {"scan", "enum", "http", "vuln", "fuzz", "brute", "creds"}
SYNC_COMMANDS = {"shell", "encode", "decode"}

ASYNC_HANDLERS = {
    "scan": cmd_scan, "enum": cmd_enum, "http": cmd_http,
    "vuln": cmd_vuln, "fuzz": cmd_fuzz, "brute": cmd_brute, "creds": cmd_creds,
}
SYNC_HANDLERS = {
    "shell": cmd_shell, "encode": cmd_encode, "decode": cmd_decode,
}


async def run_async(args):
    return await ASYNC_HANDLERS[args.command](args)


def main():
    parser = build_parser()
    args = parser.parse_args()

    print_banner()

    if args.command in ASYNC_COMMANDS:
        report = asyncio.run(run_async(args))
        print_results(args.command, report)
    else:
        report = SYNC_HANDLERS[args.command](args)

    if report and hasattr(args, "output") and args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        print_saved(str(out))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\x1b[90maborted\x1b[0m")
        sys.exit(130)
