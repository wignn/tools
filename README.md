# 🛠 Tools

Collection of security and reconnaissance utilities.

## Toolkit

| Tool | Stack | Description |
|---|---|---|
| [`github-scan`](github-scan/) | Node.js | GitHub OSINT deep scanner — repos, gists, commits, secrets, media |
| [`image-detection`](image-detection/) | Python / Flask | Image forensic suite — EXIF, GEOINT, OCR, perceptual hashing |
| [`pen`](pen/) | Python | Network penetration testing toolkit — port scan, banner grab, HTTP recon, subdomain enum |
| [`web-scraping`](web-scraping/) | Rust | Web security recon scanner — secrets, headers, endpoints, JS analysis |

## Quick Start

Each tool is self-contained with its own dependencies and README.
Navigate to the tool directory for setup instructions.

```bash
cd github-scan && npm install
cd image-detection && pip install -r requirements.txt
cd pen && pip install -r requirements.txt
cd web-scraping && cargo build --release
```

## License

[MIT](LICENSE)
