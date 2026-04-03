FROM python:3.12-slim

LABEL org.opencontainers.image.source="https://github.com/simpli-support/simpli-redact"
LABEL org.opencontainers.image.description="PII detection and data sanitization for AI-safe support data"

WORKDIR /app
COPY pyproject.toml .
COPY src/ src/
RUN pip install --no-cache-dir . \
    && addgroup --system appgroup \
    && adduser --system --ingroup appgroup appuser

USER appuser
EXPOSE 8014

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8014/health')"

CMD ["uvicorn", "simpli_redact.app:app", "--host", "0.0.0.0", "--port", "8014"]
