"""
API endpoint tests for the DLP Policy Service (policy/service.py).

Uses FastAPI's TestClient for synchronous testing without starting
a real server. Tika extraction is mocked.
"""

import base64
import pytest
from unittest.mock import patch, AsyncMock

from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def client():
    """Create a TestClient for the DLP Policy Service."""
    # Patch extract_text before importing the app so the pipeline
    # doesn't actually call Tika during tests.
    with patch("scanner.pipeline.extract_text") as mock_extract:
        from scanner.extractor import ExtractionResult
        mock_extract.return_value = ExtractionResult(text="", metadata={})

        from policy.service import app
        with TestClient(app) as c:
            yield c, mock_extract


# ---------------------------------------------------------------------------
# Health endpoint
# ---------------------------------------------------------------------------

class TestHealthEndpoint:
    def test_health_returns_200(self, client):
        c, _ = client
        response = c.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] in ("ok", "degraded", "error")
        assert "tika" in data
        assert "presidio" in data


# ---------------------------------------------------------------------------
# Rules endpoint
# ---------------------------------------------------------------------------

class TestRulesEndpoint:
    def test_list_rules_returns_rules(self, client):
        c, _ = client
        response = c.get("/api/v1/rules")
        assert response.status_code == 200
        rules = response.json()
        assert isinstance(rules, list)
        assert len(rules) > 0
        # Each rule should have an id and type.
        for rule in rules:
            assert "id" in rule
            assert "type" in rule


# ---------------------------------------------------------------------------
# Scan endpoint
# ---------------------------------------------------------------------------

class TestScanEndpoint:
    def test_scan_clean_file_allowed(self, client):
        """A clean file should be ALLOWED."""
        c, mock_extract = client
        from scanner.extractor import ExtractionResult
        mock_extract.return_value = ExtractionResult(
            text="Just a normal document.",
            metadata={},
        )

        payload = {
            "filename": "clean.txt",
            "content_type": "text/plain",
            "file_base64": base64.b64encode(b"Just a normal document.").decode(),
            "source_ip": "192.168.1.100",
            "destination_host": "example.com",
        }
        response = c.post("/api/v1/scan", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["action"] == "ALLOW"
        assert len(data["matched_rules"]) == 0

    def test_scan_sensitive_file_blocked(self, client):
        """A file with an Employee ID should be BLOCKED."""
        c, mock_extract = client
        from scanner.extractor import ExtractionResult
        mock_extract.return_value = ExtractionResult(
            text="Employee: EMP-123456",
            metadata={},
        )

        payload = {
            "filename": "sensitive.txt",
            "content_type": "text/plain",
            "file_base64": base64.b64encode(b"Employee: EMP-123456").decode(),
            "source_ip": "192.168.1.100",
            "destination_host": "example.com",
        }
        response = c.post("/api/v1/scan", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["action"] == "BLOCK"
        assert "EMP_ID" in data["matched_rules"]

    def test_scan_invalid_base64_returns_400(self, client):
        """Invalid Base64 should return 400."""
        c, _ = client
        payload = {
            "filename": "bad.txt",
            "content_type": "text/plain",
            "file_base64": "not-valid-base64!!!",
            "source_ip": "192.168.1.100",
            "destination_host": "example.com",
        }
        response = c.post("/api/v1/scan", json=payload)
        assert response.status_code == 400

    def test_scan_returns_duration(self, client):
        """Scan response should include scan_duration_ms."""
        c, mock_extract = client
        from scanner.extractor import ExtractionResult
        mock_extract.return_value = ExtractionResult(text="hello", metadata={})

        payload = {
            "filename": "test.txt",
            "content_type": "text/plain",
            "file_base64": base64.b64encode(b"hello").decode(),
            "source_ip": "10.0.0.1",
            "destination_host": "test.com",
        }
        response = c.post("/api/v1/scan", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert "scan_duration_ms" in data
        assert data["scan_duration_ms"] >= 0
