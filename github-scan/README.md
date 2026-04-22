# github-scan

GitHub OSINT deep scanner. Concurrent analysis of repositories, gists, and commit history for sensitive data leaks, exposed credentials, and media files.

## Features

- Concurrent scanning across all repos and branches
- Commit history analysis for leaked secrets
- Gist scanning
- Email harvesting from commits
- Media file detection and download
- Configurable rate limiting and batching
- JSON report export with severity grading

## Setup

```bash
npm install
cp .env.example .env
```

Add your GitHub personal access token to `.env`:

```
GITHUB_TOKEN=ghp_your_token_here
```

Without a token the API limit is 60 req/hr. With a token: 5,000 req/hr.

## Usage

```bash
node main.js <username> [options]
```

### Options

| Flag | Description |
|---|---|
| `-h, --help` | Show help |
| `--no-download` | Skip media downloads |
| `-o, --output <dir>` | Output directory for downloads |
| `--max-repos <n>` | Limit repos to scan |

### Examples

```bash
node main.js octocat
node main.js torvalds --max-repos 10
node main.js defunkt --no-download -o ./output
```

## Output

Generates `osint_<username>_<timestamp>.json` with:
- Profile information
- Discovered emails
- Exposed secrets (API keys, tokens, credentials)
- Suspicious files
- Media file inventory
- Language breakdown
- Risk severity: `CRITICAL` / `WARNING` / `CLEAN`

## Project Structure

```
├── main.js            entrypoint
├── src/
│   ├── cli.js         argument parsing
│   ├── colors.js      terminal colors
│   ├── config.js      scan configuration
│   ├── detection.js   secret pattern matching
│   ├── github.js      GitHub API client
│   ├── http.js        HTTP utilities + concurrency
│   ├── reporter.js    output formatting
│   └── scanner.js     scan orchestration
```
