"""Tests for the FastAPI application."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from simpli_redact.app import app


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


# ---------------------------------------------------------------------------
# Health (unversioned)
# ---------------------------------------------------------------------------


def test_health(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


# ---------------------------------------------------------------------------
# Detect
# ---------------------------------------------------------------------------


def test_detect(client: TestClient) -> None:
    response = client.post(
        "/api/v1/detect",
        json={"texts": [{"text": "My email is test@example.com"}]},
    )
    assert response.status_code == 200
    data = response.json()
    assert "scan_id" in data
    assert data["total_texts"] == 1
    assert len(data["results"]) == 1
    assert "entities" in data["results"][0]
    assert "has_pii" in data["results"][0]
    assert "total_pii_found" in data


def test_detect_empty_texts(client: TestClient) -> None:
    response = client.post("/api/v1/detect", json={"texts": []})
    assert response.status_code == 422


def test_detect_empty_text_content(client: TestClient) -> None:
    response = client.post("/api/v1/detect", json={"texts": [{"text": ""}]})
    assert response.status_code == 422


# ---------------------------------------------------------------------------
# Redact
# ---------------------------------------------------------------------------


def test_redact(client: TestClient) -> None:
    response = client.post(
        "/api/v1/redact",
        json={"texts": [{"text": "Call me at 555-1234"}]},
    )
    assert response.status_code == 200
    data = response.json()
    assert "scan_id" in data
    assert data["total_texts"] == 1
    assert len(data["results"]) == 1
    assert "redacted_text" in data["results"][0]
    assert "original_text" in data["results"][0]


def test_redact_with_replacement(client: TestClient) -> None:
    response = client.post(
        "/api/v1/redact",
        json={
            "texts": [{"text": "SSN: 123-45-6789"}],
            "replacement": "***",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["total_texts"] == 1
    assert len(data["results"]) == 1


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------


def test_scan(client: TestClient) -> None:
    response = client.post(
        "/api/v1/scan",
        json={"texts": [{"text": "Some text here"}, {"text": "More text"}]},
    )
    assert response.status_code == 200
    data = response.json()
    assert "scan_id" in data
    assert "summary" in data
    summary = data["summary"]
    assert summary["total_texts"] == 2
    assert "texts_with_pii" in summary
    assert "pii_rate" in summary
    assert "by_type" in summary
    assert "high_risk_indices" in summary


# ---------------------------------------------------------------------------
# Validate
# ---------------------------------------------------------------------------


def test_validate(client: TestClient) -> None:
    response = client.post(
        "/api/v1/validate",
        json={"text": "Hello world"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "safe" in data
    assert "entities" in data
    assert "recommendation" in data


def test_validate_empty(client: TestClient) -> None:
    response = client.post("/api/v1/validate", json={"text": ""})
    assert response.status_code == 422


# ---------------------------------------------------------------------------
# Request ID middleware
# ---------------------------------------------------------------------------


def test_request_id_generated(client: TestClient) -> None:
    response = client.get("/health")
    assert "x-request-id" in response.headers


def test_request_id_forwarded(client: TestClient) -> None:
    response = client.get("/health", headers={"X-Request-ID": "custom-123"})
    assert response.headers["x-request-id"] == "custom-123"


# ---------------------------------------------------------------------------
# OpenAPI schema
# ---------------------------------------------------------------------------


def test_openapi_schema(client: TestClient) -> None:
    response = client.get("/openapi.json")
    assert response.status_code == 200
    schema = response.json()
    assert "/api/v1/detect" in schema["paths"]
    assert "/api/v1/redact" in schema["paths"]
    assert "/api/v1/scan" in schema["paths"]
    assert "/api/v1/validate" in schema["paths"]
    assert "/health" in schema["paths"]
