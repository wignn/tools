# web-scraping

Web security reconnaissance scanner built in Rust. Analyzes target websites for exposed secrets, misconfigured headers, hidden endpoints, and JavaScript vulnerabilities.

## Features

- API key and credential detection with severity grading
- Security header audit (CSP, HSTS, X-Frame-Options, etc.)
- Hidden endpoint discovery (API routes, GraphQL, WebSocket, source maps)
- Sensitive file exposure checks (.env, .git, backup files)
- JavaScript static analysis for debug flags and hardcoded secrets
- Anti-bot detection and evasion
- Headless Chrome integration for JS-rendered pages
- SOCKS proxy support
- Rate limiting and retry with backoff
- Risk scoring with letter grades (A+ through F)
- JSON report export

## Build

```bash
cargo build --release
```

Binary outputs to `target/release/web-recon`.

## Usage

```bash
web-recon <url> [url2] ...
```

### Examples

```bash
cargo run -- https://example.com
cargo run -- https://site1.com https://site2.com
```

### Environment

Set `RUST_LOG` for debug output:

```bash
RUST_LOG=info cargo run -- https://example.com
```

## Output

Reports are saved to `output/<domain>_<timestamp>.json` with:
- Risk score and letter grade
- Discovered secrets with severity
- Header analysis (pass/fail/warning)
- Exposed paths and info disclosure
- API endpoints and form actions
- JavaScript analysis findings
- Scan duration

## Project Structure

```
├── Cargo.toml
├── src/
│   ├── main.rs              entrypoint + CLI + report printer
│   ├── config.rs            scan configuration
│   ├── scanner.rs           scan orchestration
│   ├── fetcher.rs           HTTP client with retry
│   ├── browser_fetcher.rs   headless Chrome fetcher
│   ├── headers.rs           security header analysis
│   ├── secrets.rs           credential pattern matching
│   ├── endpoints.rs         endpoint extraction
│   ├── js_analyzer.rs       JavaScript static analysis
│   ├── info_disclosure.rs   sensitive file detection
│   ├── anti_bot.rs          bot detection evasion
│   ├── proxy.rs             SOCKS proxy support
│   ├── rate_limiter.rs      request throttling
│   ├── retry.rs             retry with backoff
│   ├── user_agent.rs        UA rotation
│   └── headers.rs           HTTP header utilities
```
