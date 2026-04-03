"""FastAPI application."""

from __future__ import annotations

import uuid

import structlog
from fastapi import APIRouter
from pydantic import BaseModel, Field

from simpli_redact import __version__
from simpli_core import CostTracker, create_app
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


app.include_router(v1)
