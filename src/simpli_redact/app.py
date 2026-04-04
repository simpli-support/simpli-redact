"""FastAPI application."""

from __future__ import annotations

import json as json_module
import re
import uuid
from typing import Any

import litellm
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
    text: str = Field(min_length=1, description="Text content to analyze for PII")
    context: str | None = Field(
        default=None,
        description="Optional context hint such as 'support_ticket' or 'kb_article'",
    )


class PiiEntity(BaseModel):
    type: str = Field(
        description="PII category (e.g. credit_card, ssn, email, phone, address, name)"
    )
    value: str = Field(description="The detected PII text")
    start: int = Field(description="Start character offset in the original text")
    end: int = Field(description="End character offset in the original text")
    confidence: float = Field(
        ge=0.0, le=1.0, description="Model confidence for this detection"
    )


# POST /api/v1/detect — detect PII in text


class DetectRequest(BaseModel):
    texts: list[TextInput] = Field(
        min_length=1, description="Texts to scan for PII entities"
    )


class DetectResult(BaseModel):
    index: int = Field(description="Zero-based index of the text in the request")
    entities: list[PiiEntity] = Field(description="PII entities found in this text")
    has_pii: bool = Field(description="Whether any PII was detected")


class DetectResponse(BaseModel):
    scan_id: str = Field(description="Unique identifier for this detection run")
    total_texts: int = Field(description="Number of texts that were scanned")
    results: list[DetectResult] = Field(description="Per-text detection results")
    total_pii_found: int = Field(
        description="Total PII entities found across all texts"
    )


# POST /api/v1/redact — redact PII from text


class RedactRequest(BaseModel):
    texts: list[TextInput] = Field(min_length=1, description="Texts to redact PII from")
    replacement: str | None = Field(
        default=None,
        description="Custom replacement string to use instead of default placeholders",
    )


class RedactResult(BaseModel):
    index: int = Field(description="Zero-based index of the text in the request")
    original_text: str = Field(description="Original text before redaction")
    redacted_text: str = Field(description="Text with PII replaced by placeholders")
    redactions: list[PiiEntity] = Field(description="PII entities that were redacted")
    redaction_count: int = Field(description="Number of redactions applied")


class RedactResponse(BaseModel):
    scan_id: str = Field(description="Unique identifier for this redaction run")
    total_texts: int = Field(description="Number of texts that were processed")
    results: list[RedactResult] = Field(description="Per-text redaction results")
    total_redactions: int = Field(
        description="Total redactions applied across all texts"
    )


# POST /api/v1/scan — scan a batch for PII risk summary (no redaction)


class ScanRequest(BaseModel):
    texts: list[TextInput] = Field(
        min_length=1, description="Texts to scan for PII risk assessment"
    )


class PiiRiskSummary(BaseModel):
    total_texts: int = Field(description="Number of texts that were scanned")
    texts_with_pii: int = Field(description="Number of texts containing PII")
    pii_rate: float = Field(
        ge=0.0, le=1.0, description="Fraction of texts containing PII"
    )
    by_type: dict[str, int] = Field(
        description="Count of PII occurrences grouped by type"
    )
    high_risk_indices: list[int] = Field(
        description="Indices of texts with high-risk PII such as SSN or credit card"
    )


class ScanResponse(BaseModel):
    scan_id: str = Field(description="Unique identifier for this scan run")
    summary: PiiRiskSummary = Field(
        description="Aggregated PII risk summary across all texts"
    )


# POST /api/v1/validate — check if text is safe (no PII)


class ValidateRequest(BaseModel):
    text: str = Field(min_length=1, description="Text to validate for PII safety")


class ValidateResponse(BaseModel):
    safe: bool = Field(description="Whether the text is free of PII")
    entities: list[PiiEntity] = Field(description="PII entities found, if any")
    recommendation: str = Field(
        description="Human-readable recommendation based on the scan"
    )


# ---------------------------------------------------------------------------
# Versioned API router
# ---------------------------------------------------------------------------

v1 = APIRouter(prefix="/api/v1")


PII_SYSTEM_PROMPT = """\
You are a PII detection system. Analyze the text and identify all personally \
identifiable information. Return JSON with: entities (list of objects with \
{text, label, start, end, confidence}).

Supported labels: EMAIL, PHONE, NAME, ADDRESS, SSN, CREDIT_CARD, ACCOUNT_NUMBER, \
API_KEY, DATE_OF_BIRTH, PASSWORD, IBAN, CREDENTIAL, DATE, or OTHER_PII.

Rules:
- Do NOT flag software versions (e.g., iOS 18.4, v4.2.1), product/device names \
(e.g., iPhone 15 Pro), or non-PII technical identifiers as PII.
- Classify passwords, secrets, and authentication tokens as PASSWORD.
- Classify IBANs and bank routing numbers as IBAN.
- Use DATE_OF_BIRTH only for actual birth dates. Use DATE for other dates like \
billing dates, subscription dates, etc. — but only flag dates as PII if they could \
identify a person in context.
- Use API_KEY for API keys, tokens, and secrets used for authentication.

Examples:
- "Summer2024!" in context of "my password is" → PASSWORD
- "FR76 3000 6000 0112 3456 7890 189" → IBAN
- "ak_prod_7x9mK2pL" → API_KEY
- "iOS 18.4" → NOT PII (skip)
- "iPhone 15 Pro" → NOT PII (skip)"""


def _parse_llm_json(raw: str) -> dict:
    """Extract JSON from LLM output, handling code fences and embedded JSON."""
    text = raw.strip()
    # Strip markdown code fences
    fence_match = re.search(r"```(?:json)?\s*\n?(.*?)```", text, re.DOTALL)
    if fence_match:
        text = fence_match.group(1).strip()
    # Find first { ... } block
    brace_match = re.search(r"\{.*\}", text, re.DOTALL)
    if brace_match:
        text = brace_match.group(0)
    return json_module.loads(text)


@v1.post(
    "/detect",
    response_model=DetectResponse,
    tags=["detect"],
    summary="Detect PII in texts",
)
async def detect_pii(request: DetectRequest) -> DetectResponse:
    """Detect PII entities in the provided texts."""
    scan_id = str(uuid.uuid4())
    results: list[DetectResult] = []
    total_pii = 0

    for i, text_input in enumerate(request.texts):
        messages = [
            {"role": "system", "content": PII_SYSTEM_PROMPT},
            {"role": "user", "content": text_input.text},
        ]
        response = await litellm.acompletion(
            model=settings.litellm_model,
            messages=messages,
            temperature=0.1,
        )
        cost_tracker.record_from_response(settings.litellm_model, response)

        raw_content = response.choices[0].message.content or ""
        entities: list[PiiEntity] = []
        try:
            parsed = _parse_llm_json(raw_content)
            for ent in parsed.get("entities", []):
                entities.append(
                    PiiEntity(
                        type=ent["label"].lower(),
                        value=ent["text"],
                        start=ent["start"],
                        end=ent["end"],
                        confidence=ent.get("confidence", 0.9),
                    )
                )
        except (json_module.JSONDecodeError, KeyError, TypeError) as exc:
            logger.warning("pii_detect_parse_error", index=i, error=str(exc))

        total_pii += len(entities)
        results.append(
            DetectResult(index=i, entities=entities, has_pii=len(entities) > 0)
        )

    logger.info(
        "pii_detect",
        scan_id=scan_id,
        total_texts=len(request.texts),
        total_pii=total_pii,
    )
    return DetectResponse(
        scan_id=scan_id,
        total_texts=len(request.texts),
        results=results,
        total_pii_found=total_pii,
    )


@v1.post(
    "/redact",
    response_model=RedactResponse,
    tags=["redact"],
    summary="Redact PII from texts",
)
async def redact_pii(request: RedactRequest) -> RedactResponse:
    """Redact PII from the provided texts."""
    scan_id = str(uuid.uuid4())

    # First, detect PII in all texts
    detect_request = DetectRequest(texts=request.texts)
    detect_response = await detect_pii(detect_request)

    results: list[RedactResult] = []
    total_redactions = 0

    for i, text_input in enumerate(request.texts):
        detect_result = detect_response.results[i]
        original = text_input.text
        redacted = original

        # Sort entities by start position descending so replacements don't shift offsets
        sorted_entities = sorted(
            detect_result.entities, key=lambda e: e.start, reverse=True
        )
        for entity in sorted_entities:
            placeholder = f"[REDACTED_{entity.type.upper()}]"
            redacted = redacted[: entity.start] + placeholder + redacted[entity.end :]

        total_redactions += len(detect_result.entities)
        results.append(
            RedactResult(
                index=i,
                original_text=original,
                redacted_text=redacted,
                redactions=detect_result.entities,
                redaction_count=len(detect_result.entities),
            )
        )

    logger.info(
        "pii_redact",
        scan_id=scan_id,
        total_texts=len(request.texts),
        total_redactions=total_redactions,
    )
    return RedactResponse(
        scan_id=scan_id,
        total_texts=len(request.texts),
        results=results,
        total_redactions=total_redactions,
    )


@v1.post(
    "/scan",
    response_model=ScanResponse,
    tags=["scan"],
    summary="Scan texts for PII risk summary",
)
async def scan_pii(request: ScanRequest) -> ScanResponse:
    """Scan a batch of texts for a PII risk summary (no redaction)."""
    scan_id = str(uuid.uuid4())

    system_prompt = (
        "You are a PII risk assessor. Scan the given texts and provide an overall "
        "PII risk summary. Return JSON with: risk_level (none/low/medium/high/"
        "critical), total_pii_count (int), types_found (list of PII type strings), "
        "recommendation (string)."
    )

    combined_texts = "\n---\n".join(
        f"[Text {i}]: {t.text}" for i, t in enumerate(request.texts)
    )
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": combined_texts},
    ]

    response = await litellm.acompletion(
        model=settings.litellm_model,
        messages=messages,
        temperature=0.1,
    )
    cost_tracker.record_from_response(settings.litellm_model, response)

    raw_content = response.choices[0].message.content or ""
    try:
        parsed = _parse_llm_json(raw_content)
    except (json_module.JSONDecodeError, TypeError):
        parsed = {}

    total_pii_count = int(parsed.get("total_pii_count", 0))
    types_found = parsed.get("types_found", [])
    risk_level = parsed.get("risk_level", "none")

    # Map risk level to high-risk detection
    high_risk_indices: list[int] = []
    if risk_level in ("high", "critical"):
        high_risk_indices = list(range(len(request.texts)))

    texts_with_pii = (
        total_pii_count if total_pii_count <= len(request.texts) else len(request.texts)
    )
    by_type: dict[str, int] = {t: 1 for t in types_found}

    summary = PiiRiskSummary(
        total_texts=len(request.texts),
        texts_with_pii=texts_with_pii,
        pii_rate=round(texts_with_pii / len(request.texts), 4)
        if request.texts
        else 0.0,
        by_type=by_type,
        high_risk_indices=high_risk_indices,
    )
    logger.info("pii_scan", scan_id=scan_id, total_texts=len(request.texts))
    return ScanResponse(scan_id=scan_id, summary=summary)


@v1.post(
    "/validate",
    response_model=ValidateResponse,
    tags=["validate"],
    summary="Validate text is PII-free",
)
async def validate_text(request: ValidateRequest) -> ValidateResponse:
    """Check if the provided text is safe (contains no PII)."""
    system_prompt = (
        "You are a PII validator. Check if the given text is safe to send "
        "(contains no PII). Return JSON with: safe (bool), issues (list of "
        "strings describing any PII found), risk_score (0-1 float)."
    )

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": request.text},
    ]

    response = await litellm.acompletion(
        model=settings.litellm_model,
        messages=messages,
        temperature=0.1,
    )
    cost_tracker.record_from_response(settings.litellm_model, response)

    raw_content = response.choices[0].message.content or ""
    try:
        parsed = _parse_llm_json(raw_content)
    except (json_module.JSONDecodeError, TypeError):
        parsed = {}

    is_safe = parsed.get("safe", True)
    issues = parsed.get("issues", [])

    # If not safe, run detect to get detailed entities
    entities: list[PiiEntity] = []
    if not is_safe:
        detect_resp = await detect_pii(
            DetectRequest(texts=[TextInput(text=request.text)])
        )
        if detect_resp.results:
            entities = detect_resp.results[0].entities

    recommendation = (
        "No PII detected."
        if is_safe
        else "; ".join(issues)
        if issues
        else "PII detected — review before sending."
    )

    logger.info("pii_validate", text_length=len(request.text), safe=is_safe)
    return ValidateResponse(
        safe=is_safe,
        entities=entities,
        recommendation=recommendation,
    )


# ---------------------------------------------------------------------------
# Ingest models
# ---------------------------------------------------------------------------


class SalesforceIngestRequest(BaseModel):
    instance_url: str = Field(
        default="", description="Salesforce instance URL (uses server default if empty)"
    )
    client_id: str = Field(
        default="", description="OAuth2 client ID (uses server default if empty)"
    )
    client_secret: str = Field(
        default="", description="OAuth2 client secret (uses server default if empty)"
    )
    soql_where: str = Field(
        default="", description="Optional WHERE clause filter for SOQL query"
    )
    limit: int = Field(default=100, ge=1, le=10000, description="Max records to fetch")
    mappings: list[FieldMapping] | None = Field(
        default=None,
        description="Custom field mappings (uses defaults if not provided)",
    )


class IngestResult(BaseModel):
    total: int = Field(description="Total records received")
    processed: int = Field(description="Records successfully processed")
    results: list[dict[str, Any]] = Field(description="Processing results")
    errors: list[dict[str, Any]] = Field(
        default_factory=list, description="Records that failed processing"
    )


# ---------------------------------------------------------------------------
# Ingest routes
# ---------------------------------------------------------------------------


@v1.post(
    "/ingest",
    response_model=IngestResult,
    tags=["ingest"],
    summary="Ingest texts from file",
)
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


@v1.post(
    "/ingest/salesforce",
    response_model=IngestResult,
    tags=["ingest"],
    summary="Ingest from Salesforce",
)
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
    keep = settings.preserve_unmapped_fields
    if custom_mappings:
        mapped = apply_mappings(records, custom_mappings, preserve_unmapped=keep)
    elif apply_defaults:
        mapped = apply_mappings(records, CASE_TO_TICKET, preserve_unmapped=keep)
    else:
        mapped = records

    results: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []

    for i, record in enumerate(mapped):
        try:
            subject = record.get("subject", "")
            description = (
                record.get("description")
                or record.get("body")
                or record.get("content")
                or record.get("text")
                or ""
            )
            text = (
                f"Subject: {subject}\n\n{description}".strip()
                if subject and description
                else (description or subject or "")
            )
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
