# leak-guard

Lightweight secret detection tool with built-in support for Korean service API keys.

## Features

- Detects secrets in source code before they get committed
- **Korean service support**: Kakao, Naver, Toss Payments, NHN Cloud, PortOne(Iamport), Solapi, 공공데이터포털
- **Global service support**: AWS, GitHub, Google, Stripe, Slack, JWT, and more
- Pre-commit hook integration
- JSON output for CI/CD pipelines
- Zero dependencies — pure Python

## Installation

```bash
pip install leak-guard
```

## Usage

### Scan a directory

```bash
leak-guard .
leak-guard ./src
```

### Scan a single file

```bash
leak-guard config.py
```

### Pre-commit hook

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/undo/leak-guard
    rev: v0.1.0
    hooks:
      - id: leak-guard
```

### Options

```
--pre-commit    Scan only git staged files
--format json   Output as JSON
--no-color      Disable colored output
--no-korean     Disable Korean service patterns
--severity high Only show high severity findings
```

## Supported Patterns

### Korean Services
| Service | Pattern |
|---------|---------|
| Kakao | REST API Key, JavaScript Key, Admin Key |
| Naver | Client ID, Client Secret |
| Toss Payments | Secret Key |
| NHN Cloud | AppKey |
| 공공데이터포털 | API Key |
| PortOne (Iamport) | API Key, Secret |
| Solapi (CoolSMS) | API Key, Secret |

### Global Services
AWS, GitHub, Google, Stripe, Slack Webhook, JWT, Private Keys, and generic API keys/secrets.

## Contributing

Contributions are welcome! Especially:
- New Korean service patterns (배민, 당근, 쿠팡 등)
- Improved regex accuracy
- Additional test cases

## License

MIT
