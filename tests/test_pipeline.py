"""
Integration tests for the scan pipeline (scanner/pipeline.py).

These tests mock the Tika server to avoid requiring Docker, but exercise
the full extract → analyze → decision flow.
"""

import pytest
import pytest_asyncio

from unittest.mock import AsyncMock, patch, MagicMock

from scanner.pipeline import ScanPipeline, ScanDecision, create_pipeline
from scanner.analyzer import DLPAnalyzer


# ---------------------------------------------------------------------------
# Shared config
# ---------------------------------------------------------------------------

TEST_POLICIES = {
    "rules": [
        {
            "id": "EMP_ID",
            "name": "Employee ID",
            "type": "regex",
            "pattern": r"EMP-\d{6}",
            "severity": "HIGH",
            "action": "BLOCK",
        },
        {
            "id": "KEYWORD_CONFIDENTIAL",
            "name": "Confidential Keyword",
            "type": "keyword",
            "keywords": ["STRICTLY CONFIDENTIAL"],
            "case_sensitive": False,
            "severity": "MEDIUM",
            "action": "BLOCK",
        },
        {
            "id": "BLOCK_EXECUTABLES",
            "name": "Executable Files",
            "type": "file_extension",
            "extensions": [".exe", ".dll", ".bat"],
            "severity": "CRITICAL",
            "action": "BLOCK",
        },
    ],
}

FILE_POLICY = {
    "max_size_bytes": 1_000_000,  # 1 MB for testing
    "blocked_extensions": [".exe", ".dll", ".bat"],
    "allowed_types": ["text/plain", "application/pdf"],
    "encrypted_file_action": "BLOCK",
    "unsupported_type_action": "BLOCK",
    "extraction_timeout_seconds": 10,
}

SCAN_SETTINGS = {
    "ocr_enabled": False,
    "ocr_languages": ["eng"],
    "confidence_threshold": 0.7,
}


@pytest.fixture
def pipeline() -> ScanPipeline:
    """Create a pipeline with test configuration."""
    return create_pipeline(
        policies=TEST_POLICIES,
        file_policy=FILE_POLICY,
        scan_settings=SCAN_SETTINGS,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestSizeCheck:
    @pytest.mark.asyncio
    async def test_oversized_file_blocked(self, pipeline: ScanPipeline):
        """Files larger than max_size_bytes should be blocked without scanning."""
        big_file = b"x" * 2_000_000  # 2 MB > 1 MB limit
        decision = await pipeline.scan(big_file, "text/plain")
        assert decision.action == "BLOCK"
        assert "size" in decision.reason.lower()


class TestTypeCheck:
    @pytest.mark.asyncio
    async def test_unsupported_type_blocked(self, pipeline: ScanPipeline):
        """Unsupported MIME types should be blocked."""
        decision = await pipeline.scan(b"hello", "application/zip")
        assert decision.action == "BLOCK"
        assert "unsupported" in decision.reason.lower()


class TestSensitiveContent:
    @pytest.mark.asyncio
    async def test_sensitive_text_blocked(self, pipeline: ScanPipeline):
        """Text containing an Employee ID should be blocked."""
        sensitive = b"Employee record: EMP-123456, name: John Doe"

        # Mock the Tika extraction to return the text directly.
        with patch("scanner.pipeline.extract_text") as mock_extract:
            from scanner.extractor import ExtractionResult
            mock_extract.return_value = ExtractionResult(
                text=sensitive.decode("utf-8"),
                metadata={},
            )
            decision = await pipeline.scan(sensitive, "text/plain")

        assert decision.action == "BLOCK"
        assert "EMP_ID" in decision.matched_rules

    @pytest.mark.asyncio
    async def test_keyword_blocked(self, pipeline: ScanPipeline):
        """Text containing a confidential keyword should be blocked."""
        text = b"This is STRICTLY CONFIDENTIAL information."

        with patch("scanner.pipeline.extract_text") as mock_extract:
            from scanner.extractor import ExtractionResult
            mock_extract.return_value = ExtractionResult(
                text=text.decode("utf-8"),
                metadata={},
            )
            decision = await pipeline.scan(text, "text/plain")

        assert decision.action == "BLOCK"
        assert "KEYWORD_CONFIDENTIAL" in decision.matched_rules


class TestCleanContent:
    @pytest.mark.asyncio
    async def test_clean_text_allowed(self, pipeline: ScanPipeline):
        """Clean text (no sensitive data) should be allowed."""
        clean = b"Just a normal business document about meeting schedules."

        with patch("scanner.pipeline.extract_text") as mock_extract:
            from scanner.extractor import ExtractionResult
            mock_extract.return_value = ExtractionResult(
                text=clean.decode("utf-8"),
                metadata={},
            )
            decision = await pipeline.scan(clean, "text/plain")

        assert decision.action == "ALLOW"
        assert len(decision.matched_rules) == 0


class TestEncryptedFile:
    @pytest.mark.asyncio
    async def test_encrypted_pdf_blocked(self, pipeline: ScanPipeline):
        """Encrypted files should be blocked per policy."""
        from scanner.extractor import ExtractionError

        with patch("scanner.pipeline.extract_text") as mock_extract:
            mock_extract.side_effect = ExtractionError(
                "Document is encrypted", reason="encrypted"
            )
            decision = await pipeline.scan(b"encrypted-pdf-bytes", "application/pdf")

        assert decision.action == "BLOCK"
        assert "encrypted" in decision.reason.lower()


class TestExtractionFailure:
    @pytest.mark.asyncio
    async def test_extraction_timeout_blocked(self, pipeline: ScanPipeline):
        """Extraction timeouts should result in BLOCK (fail-safe)."""
        from scanner.extractor import ExtractionError

        with patch("scanner.pipeline.extract_text") as mock_extract:
            mock_extract.side_effect = ExtractionError(
                "Timed out", reason="timeout"
            )
            decision = await pipeline.scan(b"some bytes", "text/plain")

        assert decision.action == "BLOCK"


class TestScanDecisionFields:
    @pytest.mark.asyncio
    async def test_decision_has_duration(self, pipeline: ScanPipeline):
        """ScanDecision should always include scan_duration_ms."""
        with patch("scanner.pipeline.extract_text") as mock_extract:
            from scanner.extractor import ExtractionResult
            mock_extract.return_value = ExtractionResult(text="hello", metadata={})
            decision = await pipeline.scan(b"hello", "text/plain")

        assert decision.scan_duration_ms >= 0
        assert decision.file_size == 5
        assert decision.mime_type == "text/plain"


class TestExtensionCheck:
    @pytest.mark.asyncio
    async def test_exe_file_blocked_by_rule(self, pipeline: ScanPipeline):
        """Files with .exe extension should be blocked."""
        decision = await pipeline.scan(
            file_bytes=b"MZ\x90\x00\x03fake-executable",
            mime_type="application/x-dosexec",
            filename="malicious_payload.exe",
        )
        assert decision.action == "BLOCK"
        assert any("EXE" in r or "EXTENSION" in r for r in decision.matched_rules)
        assert ".exe" in decision.reason.lower()
