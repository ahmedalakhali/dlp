"""
Scan Pipeline — orchestrates text extraction, OCR, and pattern analysis.

This is the central decision engine.  Given raw file bytes and a MIME type
it produces a definitive ALLOW or BLOCK verdict.

Flow::

    File bytes + MIME
        → Size check
        → Type check
        → Tika extraction
        → (optional) OCR fallback
        → Presidio analysis
        → ScanDecision
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Literal

from scanner.extractor import extract_text, ExtractionError
from scanner.analyzer import DLPAnalyzer, Match
from scanner.ocr import is_available as ocr_available, extract_text_from_image, is_image_type

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data class for the scan verdict
# ---------------------------------------------------------------------------

@dataclass
class ScanDecision:
    """The final verdict for a scanned file."""

    action: Literal["ALLOW", "BLOCK"]
    reason: str
    matched_rules: list[str] = field(default_factory=list)
    scan_duration_ms: int = 0
    file_size: int = 0
    mime_type: str = ""


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

class ScanPipeline:
    """Orchestrates the full file-scanning workflow.

    Args:
        analyzer:    A configured :class:`DLPAnalyzer` instance.
        file_policy: Dict with keys ``max_size_bytes``, ``allowed_types``,
                     ``encrypted_file_action``, ``unsupported_type_action``,
                     ``extraction_timeout_seconds``.
        scan_settings: Dict with keys ``ocr_enabled``, ``ocr_languages``,
                       ``confidence_threshold``.
    """

    def __init__(
        self,
        analyzer: DLPAnalyzer,
        file_policy: dict[str, Any],
        scan_settings: dict[str, Any],
    ) -> None:
        self.analyzer = analyzer
        self.file_policy = file_policy
        self.scan_settings = scan_settings

    async def scan(
        self,
        file_bytes: bytes,
        mime_type: str,
        tika_url: str = "http://localhost:9998",
    ) -> ScanDecision:
        """Run the full scan pipeline on a file.

        Args:
            file_bytes: Raw file content.
            mime_type:  MIME type of the file.
            tika_url:   Base URL of the running Tika server.

        Returns:
            A :class:`ScanDecision` with the verdict.
        """
        start = time.perf_counter()

        file_size = len(file_bytes)

        def _elapsed_ms() -> int:
            return int((time.perf_counter() - start) * 1000)

        # --- 1. Size check ------------------------------------------------
        max_size = self.file_policy.get("max_size_bytes", 52_428_800)
        if file_size > max_size:
            return ScanDecision(
                action="BLOCK",
                reason=f"File exceeds maximum size ({file_size:,} > {max_size:,} bytes)",
                scan_duration_ms=_elapsed_ms(),
                file_size=file_size,
                mime_type=mime_type,
            )

        # --- 2. Type check ------------------------------------------------
        allowed_types = self.file_policy.get("allowed_types", [])
        unsupported_action = self.file_policy.get("unsupported_type_action", "BLOCK")

        if allowed_types and mime_type not in allowed_types:
            # Images may be allowed through for OCR even if not in the list.
            if not (self.scan_settings.get("ocr_enabled") and is_image_type(mime_type)):
                if unsupported_action == "BLOCK":
                    return ScanDecision(
                        action="BLOCK",
                        reason=f"Unsupported file type: {mime_type}",
                        scan_duration_ms=_elapsed_ms(),
                        file_size=file_size,
                        mime_type=mime_type,
                    )

        # --- 3. Text extraction -------------------------------------------
        timeout = self.file_policy.get("extraction_timeout_seconds", 30)
        extracted_text = ""

        try:
            result = await extract_text(
                file_bytes=file_bytes,
                mime_type=mime_type,
                timeout=timeout,
                tika_url=tika_url,
            )
            extracted_text = result.text
        except ExtractionError as exc:
            if exc.reason == "encrypted":
                encrypted_action = self.file_policy.get("encrypted_file_action", "BLOCK")
                return ScanDecision(
                    action=encrypted_action,
                    reason="Document is encrypted or password-protected",
                    scan_duration_ms=_elapsed_ms(),
                    file_size=file_size,
                    mime_type=mime_type,
                )
            elif exc.reason == "unsupported":
                if unsupported_action == "BLOCK":
                    return ScanDecision(
                        action="BLOCK",
                        reason=f"Cannot extract text from this file type: {mime_type}",
                        scan_duration_ms=_elapsed_ms(),
                        file_size=file_size,
                        mime_type=mime_type,
                    )
            else:
                # Timeout or server error — apply fail-safe policy.
                logger.error("Extraction failed: %s", exc)
                return ScanDecision(
                    action="BLOCK",
                    reason=f"Text extraction failed: {exc}",
                    scan_duration_ms=_elapsed_ms(),
                    file_size=file_size,
                    mime_type=mime_type,
                )

        # --- 4. OCR fallback (empty text + image-like content) ------------
        if not extracted_text.strip() and self.scan_settings.get("ocr_enabled", True):
            if is_image_type(mime_type):
                extracted_text = self._run_ocr(file_bytes)
            elif file_size > 1024 and not extracted_text.strip():
                # Non-trivial file with no text — might be a scanned PDF.
                # We let it through but warn.
                logger.debug(
                    "File has %d bytes but no extracted text and is not an image type",
                    file_size,
                )

        # --- 5. No text at all → allow (nothing to scan) ------------------
        if not extracted_text.strip():
            return ScanDecision(
                action="ALLOW",
                reason="No text content found in file",
                scan_duration_ms=_elapsed_ms(),
                file_size=file_size,
                mime_type=mime_type,
            )

        # --- 6. Pattern analysis ------------------------------------------
        matches = self.analyzer.analyze(extracted_text)

        if not matches:
            return ScanDecision(
                action="ALLOW",
                reason="No sensitive data detected",
                scan_duration_ms=_elapsed_ms(),
                file_size=file_size,
                mime_type=mime_type,
            )

        # Build a human-readable reason.
        unique_rules = list(dict.fromkeys(m.rule_id for m in matches))
        rule_summary = ", ".join(
            f"{rule_id} ({sum(1 for m in matches if m.rule_id == rule_id)} match(es))"
            for rule_id in unique_rules
        )

        return ScanDecision(
            action="BLOCK",
            reason=f"Sensitive data detected: {rule_summary}",
            matched_rules=unique_rules,
            scan_duration_ms=_elapsed_ms(),
            file_size=file_size,
            mime_type=mime_type,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _run_ocr(self, file_bytes: bytes) -> str:
        """Attempt OCR on image bytes."""
        if not ocr_available():
            logger.debug("Tesseract OCR not available — skipping OCR")
            return ""

        languages = self.scan_settings.get("ocr_languages", ["eng"])
        ocr_result = extract_text_from_image(file_bytes, languages=languages)
        if ocr_result.success:
            logger.debug("OCR extracted %d characters", len(ocr_result.text))
            return ocr_result.text
        else:
            logger.warning("OCR failed: %s", ocr_result.error)
            return ""


# ---------------------------------------------------------------------------
# Convenience factory
# ---------------------------------------------------------------------------

def create_pipeline(
    policies: dict[str, Any],
    file_policy: dict[str, Any],
    scan_settings: dict[str, Any],
) -> ScanPipeline:
    """Create a :class:`ScanPipeline` from raw config dicts.

    Args:
        policies:      Full parsed policies.yaml dict.
        file_policy:   The ``file_policy`` section.
        scan_settings: The ``scan_settings`` section.

    Returns:
        A ready-to-use :class:`ScanPipeline`.
    """
    threshold = scan_settings.get("confidence_threshold", 0.7)
    analyzer = DLPAnalyzer(policies=policies, confidence_threshold=threshold)
    return ScanPipeline(
        analyzer=analyzer,
        file_policy=file_policy,
        scan_settings=scan_settings,
    )
