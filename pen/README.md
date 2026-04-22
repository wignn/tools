# pen

Modular penetration testing toolkit. Recon, vulnerability scanning, exploitation, and payload generation.

## Features

**Reconnaissance**
- Async TCP port scanner with scan profiles (quick/standard/full)
- Service banner grabbing and fingerprinting
- HTTP header analysis, technology detection, security header audit
- Subdomain enumeration via DNS bruteforce

**Vulnerability Scanning**
- SQL Injection (error-based, boolean-blind, time-blind)
- Cross-Site Scripting (reflected, DOM-based, SSTI)
- Local File Inclusion (path traversal, PHP wrappers, null byte)
- Command Injection (output-based, time-blind)
- CORS misconfiguration (wildcard, origin reflection, credential exposure)
- Open Redirect (common param detection, bypass techniques)

**Exploitation**
- Directory / endpoint fuzzer with status filtering
- HTTP auth brute force (Basic Auth + form-based with auto-calibration)
- Default credential testing (20+ services: Tomcat, Jenkins, Grafana, etc.)
- Reverse shell generator (15+ types: Bash, Python, PHP, PowerShell, etc.)
- Payload encoder/decoder (base64, URL, hex, HTML, unicode, JS charcode)

## Setup

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## Commands

### `scan` — Port Scan

```bash
python main.py scan <target> [--profile quick|standard|full] [-p 80,443]
```

### `enum` — Subdomain Enumeration

```bash
python main.py enum <domain> [-w wordlist.txt]
```

### `http` — HTTP Recon

```bash
python main.py http <url>
```

### `vuln` — Vulnerability Scan

```bash
python main.py vuln <url> [-m sqli,xss,lfi,cmdi,cors,redirect]
```

### `fuzz` — Directory Fuzzer

```bash
python main.py fuzz <url> [-w wordlist.txt] [-x .php,.html] [--status 200,301]
```

### `brute` — Auth Brute Force

```bash
python main.py brute <url> --mode basic [-U users.txt] [-P passwords.txt]
python main.py brute <url> --mode form --user-field email --pass-field pwd
```

### `creds` — Default Credentials

```bash
python main.py creds <url> [-s tomcat,jenkins,grafana]
```

### `shell` — Reverse Shell Generator

```bash
python main.py shell --list
python main.py shell -t bash-tcp -H 10.10.14.1 -P 4444
python main.py shell -t powershell -H 10.10.14.1 -P 4444 -e powershell-base64
python main.py shell --all -H 10.10.14.1 -P 4444
```

### `encode` / `decode` — Payload Transform

```bash
python main.py encode "<script>alert(1)</script>" -e base64
python main.py encode "admin' OR 1=1--" --all
python main.py decode "YWRtaW4=" -e base64
```

## Project Structure

```
├── main.py
├── requirements.txt
└── src/
    ├── config.py               scan profiles + port lists
    ├── net.py                  async socket utilities
    ├── reporter.py             terminal output formatting
    ├── port_scanner.py         async TCP port scanner
    ├── banner.py               service banner grabbing
    ├── http_recon.py           HTTP analysis + tech detection
    ├── dns_enum.py             subdomain enumeration
    ├── vuln/
    │   ├── __init__.py         orchestrator + Finding model
    │   ├── sqli.py             SQL injection scanner
    │   ├── xss.py              XSS + SSTI scanner
    │   ├── lfi.py              local file inclusion scanner
    │   ├── cmdi.py             command injection scanner
    │   ├── cors.py             CORS misconfiguration scanner
    │   └── open_redirect.py    open redirect scanner
    ├── exploit/
    │   ├── fuzzer.py           directory / endpoint fuzzer
    │   ├── bruteforce.py       HTTP auth brute force
    │   ├── default_creds.py    default credential tester
    │   ├── shells.py           reverse shell generator
    │   └── payloads.py         payload encoder / decoder
    └── util/
        ├── encoder.py          encoding utilities
        └── wordlists.py        built-in wordlists + payloads
```
