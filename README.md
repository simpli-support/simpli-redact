# Simpli Redact

PII detection and data sanitization for AI-safe support data.

## Features

- **PII detection** — identify credit cards, SSNs, emails, phone numbers, addresses, names, and account numbers
- **Text redaction** — replace detected PII with configurable replacement strings
- **Batch scanning** — scan multiple texts for PII risk summary
- **Safety validation** — check if text is safe for AI consumption
- **Model flexibility** — supports OpenAI, Azure OpenAI, Anthropic, Gemini, OpenRouter, Ollama via litellm

## Quick Start

```bash
pip install -e ".[dev]"
simpli-redact serve
```

## API

- `POST /api/v1/detect` — detect PII entities in text
- `POST /api/v1/redact` — redact PII from text
- `POST /api/v1/scan` — scan batch for PII risk summary
- `POST /api/v1/validate` — check if text is safe (no PII)
- `GET /health` — health check
- `GET /usage` — LLM token usage and cost summary

## Development

```bash
ruff check .
mypy src/
pytest
```
