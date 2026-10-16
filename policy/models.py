"""
Pydantic data models for the DLP Policy Service REST API.

All request/response schemas are defined here to ensure consistent
serialization and validation across the FastAPI endpoints.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# API request / response models
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    """Incoming scan request from the proxy add-on.

    The proxy Base64-encodes the raw file bytes so they survive JSON
    serialization without encoding issues.
    """

    filename: str = Field(..., description="Original filename of the uploaded file")
    content_type: str = Field(..., description="MIME type (e.g. application/pdf)")
    file_base64: str = Field(..., description="Base64-encoded raw file bytes")
    source_ip: str = Field(..., description="Client IP address that initiated the upload")
    destination_host: str = Field(..., description="Target website hostname")


class ScanResponse(BaseModel):
    """Scan verdict returned to the proxy add-on."""

    action: Literal["ALLOW", "BLOCK"] = Field(
        ..., description="Whether the upload is allowed or blocked"
    )
    reason: str = Field(..., description="Human-readable explanation of the decision")
    matched_rules: list[str] = Field(
        default_factory=list,
        description="IDs of policy rules that triggered (empty if allowed)",
    )
    scan_duration_ms: int = Field(..., description="Time spent scanning in milliseconds")


# ---------------------------------------------------------------------------
# Admin / info models
# ---------------------------------------------------------------------------

class RuleDefinition(BaseModel):
    """Public representation of a single policy rule (for admin endpoints)."""

    id: str
    name: str
    description: str = ""
    type: str  # "regex" | "keyword" | "presidio_builtin"
    severity: str = "MEDIUM"
    action: str = "BLOCK"


class HealthResponse(BaseModel):
    """Health-check response."""

    status: Literal["ok", "degraded", "error"]
    tika: str = Field(..., description="Tika server status")
    presidio: str = Field(..., description="Presidio engine status")
    version: str = "1.0"
