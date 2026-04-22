from __future__ import annotations

from src.config import ScanProfile


def print_banner():
    print()
    print("  \x1b[1;35m╔══════════════════════════════════════════╗\x1b[0m")
    print("  \x1b[1;35m║\x1b[0m   \x1b[1;37m⚡ Pen — Penetration Testing Toolkit\x1b[0m   \x1b[1;35m║\x1b[0m")
    print("  \x1b[1;35m╚══════════════════════════════════════════╝\x1b[0m")
    print()


def print_target(target, ip, port_count, profile: ScanProfile):
    print(f"  \x1b[90mTarget:\x1b[0m      {target}")
    if ip != target:
        print(f"  \x1b[90mResolved:\x1b[0m    {ip}")
    print(f"  \x1b[90mProfile:\x1b[0m     {profile.name}")
    print(f"  \x1b[90mPorts:\x1b[0m       {port_count}")
    print(f"  \x1b[90mTimeout:\x1b[0m     {profile.timeout}s")
    print(f"  \x1b[90mConcurrency:\x1b[0m {profile.concurrency}")
    print()


def print_results(mode, report):
    if not report:
        return
    dispatch = {
        "scan": _print_scan, "enum": _print_enum, "http": _print_http,
        "vuln": _print_vuln, "fuzz": _print_fuzz,
        "brute": _print_brute, "creds": _print_creds,
    }
    fn = dispatch.get(mode)
    if fn:
        fn(report)


def _section(title):
    print(f"  \x1b[1;36m┌─────────────────────────────────────────┐\x1b[0m")
    print(f"  \x1b[1;36m│\x1b[0m  \x1b[1;37m{title:<39}\x1b[0m \x1b[1;36m│\x1b[0m")
    print(f"  \x1b[1;36m└─────────────────────────────────────────┘\x1b[0m")
    print()


def _sev_color(sev):
    return {
        "critical": "\x1b[1;41;37m", "high": "\x1b[1;31m",
        "medium": "\x1b[1;33m", "low": "\x1b[90m", "info": "\x1b[36m",
    }.get(sev, "\x1b[0m")


def _print_scan(r):
    ports = r.get("open_ports", [])
    if not ports:
        print("  \x1b[33mNo open ports found\x1b[0m\n")
        return
    _section("Scan Results")
    print(f"  \x1b[90m{'PORT':<10} {'SERVICE':<16} {'BANNER'}\x1b[0m")
    print(f"  \x1b[90m{'─' * 55}\x1b[0m")
    for e in ports:
        banner = (e.get("banner") or "")[:60].replace("\n", " ").replace("\r", "")
        print(f"  \x1b[32m{e['port']:<10}\x1b[0m \x1b[33m{e['service']:<16}\x1b[0m \x1b[90m{banner}\x1b[0m")
    print()


def _print_enum(r):
    n = r.get("subdomains_found", 0)
    _section("Subdomain Enumeration")
    print(f"  \x1b[1m{n}\x1b[0m subdomains discovered for \x1b[1m{r['domain']}\x1b[0m\n")


def _print_http(r):
    if "error" in r:
        print(f"  \x1b[31m✗ {r['error']}\x1b[0m\n")
        return
    _section("HTTP Recon")
    print(f"  \x1b[90mURL:\x1b[0m        {r['url']}")
    if r.get("final_url") != r["url"]:
        print(f"  \x1b[90mFinal:\x1b[0m      {r['final_url']}")
    print(f"  \x1b[90mStatus:\x1b[0m     \x1b[1m{r['status']}\x1b[0m")
    if r.get("title"):
        print(f"  \x1b[90mTitle:\x1b[0m      {r['title']}")
    if r.get("server"):
        print(f"  \x1b[90mServer:\x1b[0m     {r['server']}")

    tech = r.get("technologies", [])
    if tech:
        print(f"\n  \x1b[1;33m⚙ Technologies\x1b[0m")
        for t in tech:
            print(f"    \x1b[36m•\x1b[0m {t}")

    sec = r.get("security_headers", {})
    present = sec.get("present", [])
    missing = sec.get("missing", [])
    if present:
        print(f"\n  \x1b[1;32m✓ Security Headers ({len(present)})\x1b[0m")
        for h in present:
            print(f"    \x1b[32m✓\x1b[0m {h}")
    if missing:
        print(f"\n  \x1b[1;31m✗ Missing Headers ({len(missing)})\x1b[0m")
        for h in missing:
            print(f"    \x1b[31m✗\x1b[0m {h}")

    cookies = r.get("cookies", [])
    if cookies:
        print(f"\n  \x1b[1;33m🍪 Cookies ({len(cookies)})\x1b[0m")
        for ck in cookies:
            flags = []
            if not ck["secure"]: flags.append("\x1b[31mno-secure\x1b[0m")
            if not ck["httponly"]: flags.append("\x1b[31mno-httponly\x1b[0m")
            if not ck["samesite"]: flags.append("\x1b[33mno-samesite\x1b[0m")
            f = f"  [{', '.join(flags)}]" if flags else ""
            print(f"    \x1b[90m•\x1b[0m {ck['raw']}{f}")
    print()


def _print_vuln(r):
    findings = r.get("findings", [])
    _section("Vulnerability Scan")
    print(f"  \x1b[90mTarget:\x1b[0m     {r['target']}")
    print(f"  \x1b[90mModules:\x1b[0m    {', '.join(r.get('modules_run', []))}")

    by_sev = r.get("by_severity", {})
    if by_sev:
        parts = []
        for sev in ["critical", "high", "medium", "low", "info"]:
            n = by_sev.get(sev, 0)
            if n:
                parts.append(f"{_sev_color(sev)}{n} {sev}\x1b[0m")
        if parts:
            print(f"  \x1b[90mFindings:\x1b[0m   {' '.join(parts)}")
    print()

    if not findings:
        print("  \x1b[32mNo vulnerabilities found\x1b[0m\n")
        return

    for f in findings:
        sc = _sev_color(f["severity"])
        print(f"  {sc} {f['severity'].upper():<8}\x1b[0m \x1b[1m{f['vuln_type']}\x1b[0m")
        if f.get("parameter"):
            print(f"    \x1b[90mparam:\x1b[0m   {f['parameter']}")
        if f.get("payload"):
            print(f"    \x1b[90mpayload:\x1b[0m {f['payload'][:80]}")
        if f.get("evidence"):
            print(f"    \x1b[90mevidence:\x1b[0m {f['evidence'][:100]}")
        if f.get("description"):
            print(f"    \x1b[90mdesc:\x1b[0m    {f['description']}")
        print()


def _print_fuzz(r):
    _section("Fuzzer Results")
    results = r.get("results", [])
    print(f"  \x1b[90mPaths checked:\x1b[0m {r.get('paths_checked', 0)}")
    print(f"  \x1b[90mFound:\x1b[0m         {r.get('results_found', 0)}")
    print(f"  \x1b[90mDuration:\x1b[0m      {r.get('duration', '')}\n")

    if results:
        print(f"  \x1b[90m{'STATUS':<10} {'URL':<50} {'SIZE'}\x1b[0m")
        print(f"  \x1b[90m{'─' * 70}\x1b[0m")
        for res in results:
            color = "\x1b[32m" if res["status"] < 300 else "\x1b[33m" if res["status"] < 400 else "\x1b[31m"
            redir = f" → {res['redirect']}" if res.get("redirect") else ""
            print(f"  {color}{res['status']:<10}\x1b[0m {res['url']:<50} \x1b[90m{res['length']}B{redir}\x1b[0m")
    print()


def _print_brute(r):
    _section("Brute Force Results")
    print(f"  \x1b[90mMethod:\x1b[0m      {r.get('method', '')}")
    print(f"  \x1b[90mTried:\x1b[0m       {r.get('combinations_tried', 0)}")
    print(f"  \x1b[90mDuration:\x1b[0m    {r.get('duration', '')}")
    creds = r.get("credentials_found", [])
    if creds:
        print(f"\n  \x1b[1;32m✓ Valid Credentials\x1b[0m")
        for c in creds:
            print(f"    \x1b[32m✓\x1b[0m {c['username']}:{c['password']}  [HTTP {c['status']}]")
    else:
        print(f"\n  \x1b[33mNo valid credentials found\x1b[0m")
    print()


def _print_creds(r):
    _section("Default Credential Check")
    print(f"  \x1b[90mServices:\x1b[0m    {', '.join(r.get('services_tested', []))}")
    print(f"  \x1b[90mTested:\x1b[0m      {r.get('total_tested', 0)}")
    print(f"  \x1b[90mDuration:\x1b[0m    {r.get('duration', '')}")
    creds = r.get("credentials_found", [])
    if creds:
        print(f"\n  \x1b[1;31m⚠ Default Credentials Found\x1b[0m")
        for c in creds:
            pwd = c["password"] if c["password"] else "(empty)"
            print(f"    \x1b[31m✓\x1b[0m \x1b[33m{c['service']}\x1b[0m  {c['username']}:{pwd}  [{c['status']}]")
    else:
        print(f"\n  \x1b[32mNo default credentials found\x1b[0m")
    print()


def print_shell(result):
    if "error" in result:
        return
    name = result.get("name", result.get("type", ""))
    print(f"\n  \x1b[1;33m⚡ {name}\x1b[0m")
    if result.get("encoding") and result["encoding"] != "raw":
        print(f"  \x1b[90mEncoding: {result['encoding']}\x1b[0m")
    print(f"\n  \x1b[36m{result['payload']}\x1b[0m")
    if result.get("execution"):
        print(f"\n  \x1b[90mExecution:\x1b[0m {result['execution']}")
    print()


def print_encode_result(result):
    if "encodings" in result:
        print(f"\n  \x1b[90mOriginal:\x1b[0m {result['original']}\n")
        for name, encoded in result["encodings"].items():
            print(f"  \x1b[33m{name:<16}\x1b[0m {encoded}")
        print()
    elif "result" in result:
        print(f"\n  \x1b[90m{result.get('encoding', '')}:\x1b[0m {result['result']}\n")


def print_saved(path):
    print(f"  \x1b[90mReport saved: {path}\x1b[0m\n")
