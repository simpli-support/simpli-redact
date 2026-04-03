# Simpli Redact

PII detection and data sanitization for AI-safe support data. Part of the [Simpli Support](https://simpli.support) platform.

## Features

- **PII detection** — identify credit cards, SSNs, emails, phone numbers, addresses, names, and account numbers
- **Text redaction** — replace detected PII with configurable replacement strings
- **Batch scanning** — scan multiple texts for a PII risk summary without redacting
- **Safety validation** — check whether text is safe for AI consumption
- **Configurable entity types** — choose which PII types to detect

## Quick start

```bash
cp .env.example .env
pip install -e ".[dev]"
simpli-redact serve
```

## API

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/detect` | Detect PII entities in provided texts |
| POST | `/api/v1/redact` | Redact PII from provided texts |
| POST | `/api/v1/scan` | Scan a batch of texts for PII risk summary |
| POST | `/api/v1/validate` | Check if text is safe (contains no PII) |
| GET | `/health` | Health check |
| GET | `/usage` | LLM token usage and cost summary |

## Configuration

All settings are loaded from environment variables or `.env` files via [pydantic-settings](https://docs.pydantic.dev/latest/concepts/pydantic_settings/).

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_HOST` | `0.0.0.0` | Host to bind the server to |
| `APP_PORT` | `8000` | Port to bind the server to |
| `APP_LOG_LEVEL` | `info` | Log level |
| `LITELLM_MODEL` | `openai/gpt-5-mini` | LiteLLM model identifier for PII detection |
| `CORS_ORIGINS` | `*` | Allowed CORS origins |
| `REDACT_REPLACEMENT` | `[REDACTED]` | Replacement string for redacted PII |
| `DETECT_TYPES` | `credit_card,ssn,email,phone,address,name,account_number` | Comma-separated PII types to detect |

## Development

```bash
pytest tests/ -q
ruff check .
ruff format --check .
mypy src/
```

## Docker

```bash
docker build -t simpli-redact .
docker run -p 8000:8000 simpli-redact
```

## License

MIT
