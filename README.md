# keytrap

> Lightweight, extensible secret detection that actually catches secrets. Zero dependencies.

Catch leaked API keys, tokens, and credentials **before** they reach your repository. 60+ patterns across 11 categories, with the highest out-of-box detection rate among open-source tools.

## Why keytrap?

| | **keytrap** | gitleaks | trufflehog |
|---|---|---|---|
| Detection rate | **7/7 secrets** | 0/7 | 0/7 |
| Language | Pure Python | Go | Python |
| Dependencies | **0** | - | Many |
| Setup | `pip install keytrap` | Binary download | pip + extras |
| Custom patterns | **YAML — one line** | TOML config | Complex |
| Regional support | **Built-in plugins** | Global only | Global only |
| SARIF output | Yes | Yes | No |

## Benchmark

Tested on 501 files, 100k lines, 7 embedded secrets (AWS, GitHub, PostgreSQL, RSA, Kakao, Anthropic, HuggingFace):

| Tool | Time | Lines/sec | Secrets Found |
|------|------|-----------|---------------|
| **keytrap** | 0.35s | 288k | **7/7** |
| gitleaks | 0.03s | 3,077k | 0/7 |
| trufflehog | 0.11s | 882k | 0/7 |

gitleaks and trufflehog are faster (Go binary / verified-only approach), but miss unverified secrets in file scans. keytrap prioritizes **detection coverage** — catching every secret matters more than raw speed.

```bash
# Run the comparison yourself
python benchmark_compare.py
```

## Installation

```bash
pip install keytrap
```

## Quick Start

```bash
# Scan current directory
keytrap .

# Scan a specific file
keytrap src/config.py

# Only high severity
keytrap --severity high .

# JSON output for CI/CD
keytrap --format json .

# SARIF output for GitHub Advanced Security
keytrap --format sarif . > results.sarif
```

## Advanced Features

### Entropy-based detection

Catch random/high-entropy secrets that don't match any known pattern:

```bash
keytrap --entropy .
```

### Git history scan

Scan past commits for leaked secrets:

```bash
# Scan last 50 commits
keytrap --scan-history 50

# Scan diff from a specific commit
keytrap --diff HEAD~5
```

### GitHub Action

```yaml
- uses: cobyoo/keytrap@v1
  with:
    severity: high
    format: sarif
```

## Pre-commit Hook

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/cobyoo/keytrap
    rev: v0.2.0
    hooks:
      - id: keytrap
```

## Pattern Categories

```bash
keytrap --list-categories
```

| Category | Examples | Count |
|----------|----------|-------|
| `cloud` | AWS, GCP, Azure, DigitalOcean, Heroku, Vercel, Supabase, Firebase | 14 |
| `vcs` | GitHub, GitLab, Bitbucket, npm, PyPI, RubyGems | 7 |
| `payments` | Stripe, PayPal, Square | 5 |
| `messaging` | Slack, Discord, Telegram, Twilio, SendGrid, Mailgun | 9 |
| `databases` | PostgreSQL, MySQL, MongoDB, Redis connection strings | 2 |
| `ci_cd` | CircleCI, Travis CI, Jenkins | 3 |
| `identity` | Auth0, Okta, JWT, OAuth | 4 |
| `crypto` | Private keys (RSA, EC, DSA, PGP, OpenSSH) | 2 |
| `ai_ml` | OpenAI, Anthropic, HuggingFace, Replicate, Cohere | 6 |
| `generic` | API keys, passwords, tokens, base64 private keys | 3 |
| `regional_kr` | Kakao, Naver, Toss, PortOne | 5 |

### Scan specific categories only

```bash
# Only check cloud and payments
keytrap --category cloud --category payments .

# Exclude regional patterns
keytrap --exclude-category regional_kr .
```

## Custom Patterns

Create `.keytrap.yml` in your project root:

```yaml
patterns:
  - name: "Internal Service Token"
    pattern: "MYCO_[A-Z0-9]{32}"
    severity: high
    category: custom

  - name: "Internal DB Password"
    pattern: "db_pass_[a-zA-Z0-9]{16,}"
    severity: high
    ignorecase: true

allowlist:
  - "EXAMPLE_KEY_FOR_DOCS"
  - "test_token_placeholder"
```

## Inline Ignore

Suppress a specific line:

```python
api_key = "not-a-real-key"  # keytrap:ignore
```

## CI/CD Integration

### GitHub Actions

```yaml
- name: Secret Scan
  run: |
    pip install keytrap
    keytrap --format sarif . > results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### GitLab CI

```yaml
secret-scan:
  script:
    - pip install keytrap
    - keytrap --format json . > gl-secret-detection-report.json
  artifacts:
    reports:
      secret_detection: gl-secret-detection-report.json
```

## Output Formats

**Text** (default) — human-readable with colors and redaction

**JSON** — structured output for automation

**SARIF** — GitHub Advanced Security / code scanning integration

## Contributing

Contributions welcome! Especially:
- New service patterns (open a PR with test cases)
- Regional pattern plugins
- Performance improvements

## License

MIT
