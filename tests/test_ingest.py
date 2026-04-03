"""Tests for data ingest endpoints."""

import io
import json

import pytest
from fastapi.testclient import TestClient

from simpli_redact.app import app


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


def test_ingest_csv(client: TestClient) -> None:
    csv_content = "text\nMy email is john@example.com\nCall me at 555-1234\n"
    file = io.BytesIO(csv_content.encode())
    response = client.post(
        "/api/v1/ingest",
        files={"file": ("data.csv", file, "text/csv")},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 2
    assert data["processed"] == 2
    assert len(data["results"]) == 2


def test_ingest_json(client: TestClient) -> None:
    records = [
        {"text": "My SSN is 123-45-6789"},
    ]
    file = io.BytesIO(json.dumps(records).encode())
    response = client.post(
        "/api/v1/ingest",
        files={"file": ("data.json", file, "application/json")},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    assert data["processed"] == 1


def test_ingest_salesforce_missing_credentials(client: TestClient) -> None:
    response = client.post(
        "/api/v1/ingest/salesforce",
        json={"limit": 10},
    )
    assert response.status_code == 400
    assert "credentials" in response.json()["detail"].lower()
