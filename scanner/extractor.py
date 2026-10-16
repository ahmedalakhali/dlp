"""
Tika Text Extractor — sends files to Apache Tika Server for text extraction.

Uses the Tika Server REST API (PUT /tika) via httpx for async HTTP calls.
Does NOT use the `tika` Python library (which spawns a local JVM).
"""

import httpx
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Configuration defaults (overridden by config/proxy_config.yaml at runtime)
# ---------------------------------------------------------------------------
TIKA_SERVER_URL = "http://localhost:9998"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class ExtractionResult:
    """Result of text extraction from a document."""
    text: str
    metadata: dict = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    content_type_detected: str = ""


class ExtractionError(Exception):
    """Raised when text extraction fails."""

    def __init__(self, message: str, reason: str = "unknown"):
        super().__init__(message)
        self.reason = reason  # "timeout", "unsupported", "encrypted", "server_error"


# ---------------------------------------------------------------------------
# Core extraction function
# ---------------------------------------------------------------------------
async def extract_text(
    file_bytes: bytes,
    mime_type: str,
    timeout: int = 30,
    tika_url: str = TIKA_SERVER_URL,
) -> ExtractionResult:
    """
    Extract text from a document by sending it to the Tika Server.

    Args:
        file_bytes: Raw file content.
        mime_type:  MIME type hint (e.g. "application/pdf").
        timeout:    Seconds before giving up.
        tika_url:   Base URL of the Tika Server.

    Returns:
        ExtractionResult with extracted text and metadata.

    Raises:
        ExtractionError on timeout, server error, or unsupported format.
    """
    warnings: list[str] = []

    # --- Send to Tika Server ------------------------------------------------
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(timeout, connect=2.0),
            trust_env=False,
        ) as client:
            # PUT /tika — returns plain text content
            text_response = await client.put(
                f"{tika_url}/tika",
                content=file_bytes,
                headers={
                    "Content-Type": mime_type,
                    "Accept": "text/plain",
                },
            )

            if text_response.status_code == 422:
                raise ExtractionError(
                    f"Tika cannot process this file type: {mime_type}",
                    reason="unsupported",
                )

            if text_response.status_code != 200:
                raise ExtractionError(
                    f"Tika returned HTTP {text_response.status_code}",
                    reason="server_error",
                )

            extracted_text = text_response.text.strip()

            # --- Fetch metadata separately ----------------------------------
            metadata = {}
            try:
                meta_response = await client.put(
                    f"{tika_url}/meta",
                    content=file_bytes,
                    headers={
                        "Content-Type": mime_type,
                        "Accept": "application/json",
                    },
                )
                if meta_response.status_code == 200:
                    metadata = meta_response.json()
            except Exception:
                warnings.append("Failed to retrieve metadata from Tika")

            # --- Detect encrypted documents ---------------------------------
            content_type_detected = metadata.get("Content-Type", mime_type)
            is_encrypted = _check_encrypted(metadata, extracted_text, file_bytes)
            if is_encrypted:
                raise ExtractionError(
                    "Document appears to be encrypted or password-protected",
                    reason="encrypted",
                )

            return ExtractionResult(
                text=extracted_text,
                metadata=metadata,
                warnings=warnings,
                content_type_detected=content_type_detected,
            )

    except (httpx.ConnectError, httpx.ConnectTimeout):
        # Fallback for plain text types if Tika server is offline
        if mime_type in ("text/plain", "text/csv", "application/json"):
            try:
                decoded = file_bytes.decode("utf-8")
            except UnicodeDecodeError:
                decoded = file_bytes.decode("latin-1", errors="replace")
            return ExtractionResult(
                text=decoded,
                metadata={"Content-Type": mime_type},
                warnings=[f"Tika offline at {tika_url}; decoded directly as plain text"],
                content_type_detected=mime_type,
            )
        raise ExtractionError(
            f"Cannot connect to Tika Server at {tika_url}",
            reason="server_error",
        )
    except httpx.TimeoutException:
        raise ExtractionError(
            f"Tika extraction timed out after {timeout}s",
            reason="timeout",
        )
    except ExtractionError:
        raise  # Re-raise our own errors
    except Exception as exc:
        raise ExtractionError(
            f"Unexpected extraction error: {exc}",
            reason="unknown",
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _check_encrypted(
    metadata: dict, extracted_text: str, file_bytes: bytes
) -> bool:
    """
    Heuristic check for encrypted/password-protected documents.

    Tika typically returns empty text for encrypted PDFs and sets
    metadata flags like 'pdf:encrypted' or 'X-TIKA:EXCEPTION:warn'.
    """
    # Tika explicitly flags encrypted PDFs
    if metadata.get("pdf:encrypted", "").lower() == "true":
        return True

    # Tika warns about encryption in its exception metadata
    tika_exception = metadata.get("X-TIKA:EXCEPTION:warn", "")
    if "encrypt" in tika_exception.lower():
        return True

    # Heuristic: non-trivial file with zero extracted text for PDF/DOCX/XLSX
    encrypted_mime_types = {
        "application/pdf",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    }
    content_type = metadata.get("Content-Type", "")
    if (
        content_type in encrypted_mime_types
        and len(file_bytes) > 1024
        and len(extracted_text) == 0
    ):
        return True

    return False
