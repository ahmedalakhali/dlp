"""
DLP Policy Service — FastAPI REST API.

Receives file scan requests from the mitmproxy add-on, invokes the
scanner pipeline, logs audit events, and returns ALLOW/BLOCK verdicts.

Start with::

    uvicorn policy.service:app --host 127.0.0.1 --port 8000
"""

from __future__ import annotations

import base64
import logging
from contextlib import asynccontextmanager

import httpx

from fastapi import FastAPI, HTTPException

from policy.models import ScanRequest, ScanResponse, HealthResponse
from policy.rules import RuleManager
from policy.audit import AuditLogger, create_audit_logger
from scanner.pipeline import ScanPipeline, create_pipeline

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Application state (initialised during lifespan)
# ---------------------------------------------------------------------------

_pipeline: ScanPipeline | None = None
_rule_manager: RuleManager | None = None
_audit_logger: AuditLogger | None = None
_tika_url: str = "http://localhost:9998"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialise shared resources on startup, clean up on shutdown."""
    global _pipeline, _rule_manager, _audit_logger

    # Load rules.
    _rule_manager = RuleManager()
    _rule_manager.load("config/policies.yaml")

    policies = _rule_manager.get_policies_dict()
    file_policy = _rule_manager.get_file_policy()
    scan_settings = _rule_manager.get_scan_settings()

    # Build the scan pipeline.
    _pipeline = create_pipeline(
        policies=policies,
        file_policy=file_policy,
        scan_settings=scan_settings,
    )

    # Set up audit logger.
    _audit_logger = create_audit_logger("config/logging_config.yaml")
    await _audit_logger.initialize()

    logger.info("DLP Policy Service started")

    yield

    # Shutdown.
    if _audit_logger:
        await _audit_logger.close()
    logger.info("DLP Policy Service stopped")


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="DLP Policy Service",
    description="Enterprise Data Loss Prevention — scan files for sensitive data",
    version="1.0.0",
    lifespan=lifespan,
)


@app.post("/api/v1/scan", response_model=ScanResponse)
async def scan_file(request: ScanRequest) -> ScanResponse:
    """Scan a file and return an ALLOW or BLOCK decision.

    The proxy add-on sends Base64-encoded file bytes along with metadata.
    The pipeline extracts text, runs pattern analysis, and returns a verdict.
    """
    if _pipeline is None:
        raise HTTPException(status_code=503, detail="Pipeline not initialized")

    try:
        file_bytes = base64.b64decode(request.file_base64)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid Base64 in file_base64")

    mime_type = request.content_type
    if mime_type in ("", "application/octet-stream") and request.filename:
        import mimetypes
        guessed_type, _ = mimetypes.guess_type(request.filename)
        if guessed_type:
            mime_type = guessed_type

    decision = await _pipeline.scan(
        file_bytes=file_bytes,
        mime_type=mime_type,
        tika_url=_tika_url,
    )

    response = ScanResponse(
        action=decision.action,
        reason=decision.reason,
        matched_rules=decision.matched_rules,
        scan_duration_ms=decision.scan_duration_ms,
    )

    # Audit log (fire-and-forget style, but awaited for reliability).
    if _audit_logger:
        try:
            await _audit_logger.log_event(request, response, file_bytes)
        except Exception:
            logger.exception("Failed to write audit log")

    return response


@app.get("/api/v1/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    """Health check — verify Tika and Presidio are operational."""
    tika_status = "unknown"
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(f"{_tika_url}/tika")
            tika_status = "ok" if resp.status_code == 200 else f"HTTP {resp.status_code}"
    except Exception as exc:
        tika_status = f"error: {exc}"

    presidio_status = "loaded" if _pipeline else "not loaded"

    overall = "ok"
    if "error" in tika_status:
        overall = "degraded"
    if _pipeline is None:
        overall = "error"

    return HealthResponse(
        status=overall,
        tika=tika_status,
        presidio=presidio_status,
    )


@app.get("/api/v1/rules")
async def list_rules():
    """Return all active policy rule definitions."""
    if _rule_manager is None:
        raise HTTPException(status_code=503, detail="Rules not loaded")
    return _rule_manager.get_all()
