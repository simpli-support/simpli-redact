"""FastAPI application."""

from __future__ import annotations

import json as json_module
import uuid
from typing import Any

import structlog
from fastapi import APIRouter, File, Form, UploadFile
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from simpli_core import CostTracker, create_app
from simpli_core.connectors import (
    FieldMapping,
    FileConnector,
    SalesforceConnector,
    apply_mappings,
)
from simpli_core.connectors.mapping import CASE_TO_TICKET

from simpli_redact import __version__
from simpli_redact.settings import settings

cost_tracker = CostTracker()
logger = structlog.get_logger(__name__)

app = create_app(
    title="Simpli Redact",
    version=__version__,
    description="PII detection and data sanitization for AI-safe support data",
    settings=settings,
    cors_origins=settings.cors_origins,
    cost_tracker=cost_tracker,
)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class TextInput(BaseModel):
    text: str = Field(min_length=1)
    context: str | None = None  # e.g. "support_ticket", "kb_article"


class PiiEntity(BaseModel):
    type: str  # credit_card, ssn, email, phone, address, name, account_number
    value: str
    start: int
    end: int
    confidence: float = Field(ge=0.0, le=1.0)


# POST /api/v1/detect — detect PII in text


class DetectRequest(BaseModel):
    texts: list[TextInput] = Field(min_length=1)


class DetectResult(BaseModel):
    index: int
    entities: list[PiiEntity]
    has_pii: bool


class DetectResponse(BaseModel):
    scan_id: str
    total_texts: int
    results: list[DetectResult]
    total_pii_found: int


# POST /api/v1/redact — redact PII from text


class RedactRequest(BaseModel):
    texts: list[TextInput] = Field(min_length=1)
    replacement: str | None = None  # override default replacement string


class RedactResult(BaseModel):
    index: int
    original_text: str
    redacted_text: str
    redactions: list[PiiEntity]
    redaction_count: int


class RedactResponse(BaseModel):
    scan_id: str
    total_texts: int
    results: list[RedactResult]
    total_redactions: int


# POST /api/v1/scan — scan a batch for PII risk summary (no redaction)


class ScanRequest(BaseModel):
    texts: list[TextInput] = Field(min_length=1)


class PiiRiskSummary(BaseModel):
    total_texts: int
    texts_with_pii: int
    pii_rate: float = Field(ge=0.0, le=1.0)
    by_type: dict[str, int]  # pii_type -> count
    high_risk_indices: list[int]  # indices with sensitive PII (SSN, credit card)


class ScanResponse(BaseModel):
    scan_id: str
    summary: PiiRiskSummary


# POST /api/v1/validate — check if text is safe (no PII)


class ValidateRequest(BaseModel):
    text: str = Field(min_length=1)


class ValidateResponse(BaseModel):
    safe: bool
    entities: list[PiiEntity]
    recommendation: str


# ---------------------------------------------------------------------------
# Versioned API router
# ---------------------------------------------------------------------------

v1 = APIRouter(prefix="/api/v1")


@v1.post("/detect", response_model=DetectResponse, tags=["detect"])
async def detect_pii(request: DetectRequest) -> DetectResponse:
    """Detect PII entities in the provided texts."""
    scan_id = str(uuid.uuid4())
    # TODO: replace stub with real PII detection via litellm call
    # response = await litellm.acompletion(model=settings.litellm_model, messages=...)
    # cost_tracker.record_from_response(settings.litellm_model, response)
    results = [
        DetectResult(index=i, entities=[], has_pii=False)
        for i in range(len(request.texts))
    ]
    logger.info("pii_detect", scan_id=scan_id, total_texts=len(request.texts))
    return DetectResponse(
        scan_id=scan_id,
        total_texts=len(request.texts),
        results=results,
        total_pii_found=0,
    )


@v1.post("/redact", response_model=RedactResponse, tags=["redact"])
async def redact_pii(request: RedactRequest) -> RedactResponse:
    """Redact PII from the provided texts."""
    scan_id = str(uuid.uuid4())
    # TODO: replace stub with real PII detection and redaction via litellm call
    # response = await litellm.acompletion(model=settings.litellm_model, messages=...)
    # cost_tracker.record_from_response(settings.litellm_model, response)
    results = [
        RedactResult(
            index=i,
            original_text=t.text,
            redacted_text=t.text,
            redactions=[],
            redaction_count=0,
        )
        for i, t in enumerate(request.texts)
    ]
    logger.info("pii_redact", scan_id=scan_id, total_texts=len(request.texts))
    return RedactResponse(
        scan_id=scan_id,
        total_texts=len(request.texts),
        results=results,
        total_redactions=0,
    )


@v1.post("/scan", response_model=ScanResponse, tags=["scan"])
async def scan_pii(request: ScanRequest) -> ScanResponse:
    """Scan a batch of texts for a PII risk summary (no redaction)."""
    scan_id = str(uuid.uuid4())
    # TODO: replace stub with real PII scanning via litellm call
    # response = await litellm.acompletion(model=settings.litellm_model, messages=...)
    # cost_tracker.record_from_response(settings.litellm_model, response)
    summary = PiiRiskSummary(
        total_texts=len(request.texts),
        texts_with_pii=0,
        pii_rate=0.0,
        by_type={},
        high_risk_indices=[],
    )
    logger.info("pii_scan", scan_id=scan_id, total_texts=len(request.texts))
    return ScanResponse(scan_id=scan_id, summary=summary)


@v1.post("/validate", response_model=ValidateResponse, tags=["validate"])
async def validate_text(request: ValidateRequest) -> ValidateResponse:
    """Check if the provided text is safe (contains no PII)."""
    # TODO: replace stub with real PII validation via litellm call
    # response = await litellm.acompletion(model=settings.litellm_model, messages=...)
    # cost_tracker.record_from_response(settings.litellm_model, response)
    logger.info("pii_validate", text_length=len(request.text))
    return ValidateResponse(
        safe=True,
        entities=[],
        recommendation="No PII detected.",
    )


# ---------------------------------------------------------------------------
# Ingest models
# ---------------------------------------------------------------------------


class SalesforceIngestRequest(BaseModel):
    instance_url: str = ""
    client_id: str = ""
    client_secret: str = ""
    soql_where: str = ""
    limit: int = Field(default=100, ge=1, le=10000)
    mappings: list[FieldMapping] | None = None


class IngestResult(BaseModel):
    total: int
    processed: int
    results: list[dict[str, Any]]
    errors: list[dict[str, Any]] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Ingest routes
# ---------------------------------------------------------------------------


@v1.post("/ingest", response_model=IngestResult, tags=["ingest"])
async def ingest_file(
    file: UploadFile = File(...),  # noqa: B008
    mappings: str | None = Form(default=None),
) -> IngestResult:
    """Ingest texts from a file and detect PII in each one."""
    records = FileConnector.parse(file.file, format=_detect_format(file.filename))

    field_mappings: list[FieldMapping] | None = None
    if mappings:
        field_mappings = [FieldMapping(**m) for m in json_module.loads(mappings)]

    return await _process_records(records, field_mappings, apply_defaults=False)


@v1.post("/ingest/salesforce", response_model=IngestResult, tags=["ingest"])
async def ingest_salesforce(request: SalesforceIngestRequest) -> IngestResult:
    """Pull cases from Salesforce and detect PII in each one."""
    instance_url = request.instance_url or settings.salesforce_instance_url
    client_id = request.client_id or settings.salesforce_client_id
    client_secret = request.client_secret or settings.salesforce_client_secret

    if not all([instance_url, client_id, client_secret]):
        return JSONResponse(  # type: ignore[return-value]
            status_code=400,
            content={
                "detail": "Salesforce credentials required"
                " (instance_url, client_id, client_secret)"
            },
        )

    connector = SalesforceConnector(
        instance_url=instance_url,
        client_id=client_id,
        client_secret=client_secret,
    )
    records = connector.get_cases(where=request.soql_where, limit=request.limit)

    return await _process_records(records, request.mappings)


def _detect_format(filename: str | None) -> str:
    if not filename:
        return "csv"
    suffix = filename.rsplit(".", 1)[-1].lower() if "." in filename else "csv"
    return suffix if suffix in FileConnector.SUPPORTED_FORMATS else "csv"


async def _process_records(
    records: list[dict[str, Any]],
    custom_mappings: list[FieldMapping] | None,
    *,
    apply_defaults: bool = True,
) -> IngestResult:
    if custom_mappings:
        mapped = apply_mappings(records, custom_mappings)
    elif apply_defaults:
        mapped = apply_mappings(records, CASE_TO_TICKET)
    else:
        mapped = records

    results: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []

    for i, record in enumerate(mapped):
        try:
            text = record.get("text", record.get("description", record.get("body", "")))
            req = DetectRequest(texts=[TextInput(text=text)])
            result = await detect_pii(req)
            results.append(result.model_dump())
        except Exception as exc:
            errors.append({"index": i, "error": str(exc), "record": record})

    return IngestResult(
        total=len(records),
        processed=len(results),
        results=results,
        errors=errors,
    )


app.include_router(v1)
