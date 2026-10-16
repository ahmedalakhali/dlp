"""
End-to-End DLP Test — verifies the full proxy → scan → block flow.

This test sends upload requests through the DLP proxy to the test upload
server and verifies that:
  • Sensitive files → HTTP 403 (blocked), test server receives NOTHING.
  • Clean files    → HTTP 200 (allowed), test server receives the file.

Prerequisites (must be running before this test):
  1. Apache Tika:    docker-compose up -d tika
  2. Policy Service: uvicorn policy.service:app --host 127.0.0.1 --port 8000
  3. mitmproxy:      mitmdump --listen-host 127.0.0.1 --listen-port 8080 -s proxy/addon.py
  4. Upload Server:  python scripts/test_upload_server.py

Or simply: .\\scripts\\start_all.ps1 && python scripts/test_upload_server.py

Run::

    python -m pytest tests/test_end_to_end.py -v
"""

import os
import pytest
import requests
from pathlib import Path

# Configuration
PROXY_URL = "http://127.0.0.1:8080"
UPLOAD_SERVER_URL = "http://127.0.0.1:5000"
PROXY_DICT = {"http": PROXY_URL, "https": PROXY_URL}

FIXTURES_DIR = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Skip if services aren't running
# ---------------------------------------------------------------------------

def _services_running() -> bool:
    """Check if the proxy, policy service, and upload server are reachable."""
    try:
        requests.get(UPLOAD_SERVER_URL, timeout=2)
        requests.get(f"{UPLOAD_SERVER_URL}/received", timeout=2)
        return True
    except Exception:
        return False


skip_if_no_services = pytest.mark.skipif(
    not _services_running(),
    reason="End-to-end services not running (proxy, policy, upload server)",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _clear_received():
    """Delete all files from the test upload server."""
    requests.delete(f"{UPLOAD_SERVER_URL}/received", timeout=5)


def _get_received():
    """Get the list of received files from the test upload server."""
    resp = requests.get(f"{UPLOAD_SERVER_URL}/received", timeout=5)
    return resp.json()


def _upload_file_through_proxy(filepath: Path, filename: str = None):
    """Upload a file through the DLP proxy to the test upload server."""
    if filename is None:
        filename = filepath.name

    with open(filepath, "rb") as f:
        return requests.post(
            f"{UPLOAD_SERVER_URL}/upload",
            files={"file": (filename, f)},
            proxies=PROXY_DICT,
            timeout=30,
        )


def _upload_raw_through_proxy(data: bytes, content_type: str = "application/octet-stream"):
    """Upload raw bytes through the proxy."""
    return requests.post(
        f"{UPLOAD_SERVER_URL}/upload",
        data=data,
        headers={"Content-Type": content_type},
        proxies=PROXY_DICT,
        timeout=30,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@skip_if_no_services
class TestSensitiveFilesBlocked:
    """Sensitive files must be BLOCKED — upload server should receive nothing."""

    def setup_method(self):
        _clear_received()

    def test_sensitive_txt_blocked(self):
        fixture = FIXTURES_DIR / "sensitive.txt"
        if not fixture.exists():
            pytest.skip("Fixture not generated")

        resp = _upload_file_through_proxy(fixture)
        assert resp.status_code == 403, f"Expected 403, got {resp.status_code}"

        # Verify server received nothing.
        received = _get_received()
        assert received["count"] == 0, "Upload server should NOT have received the file"

    def test_ssn_blocked(self):
        fixture = FIXTURES_DIR / "ssn_test.txt"
        if not fixture.exists():
            pytest.skip("Fixture not generated")

        resp = _upload_file_through_proxy(fixture)
        assert resp.status_code == 403

        received = _get_received()
        assert received["count"] == 0

    def test_keyword_blocked(self):
        fixture = FIXTURES_DIR / "keyword_test.txt"
        if not fixture.exists():
            pytest.skip("Fixture not generated")

        resp = _upload_file_through_proxy(fixture)
        assert resp.status_code == 403

        received = _get_received()
        assert received["count"] == 0


@skip_if_no_services
class TestCleanFilesAllowed:
    """Clean files must be ALLOWED — upload server should receive them."""

    def setup_method(self):
        _clear_received()

    def test_clean_txt_allowed(self):
        fixture = FIXTURES_DIR / "clean.txt"
        if not fixture.exists():
            pytest.skip("Fixture not generated")

        resp = _upload_file_through_proxy(fixture)
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"

        # Verify server received the file.
        received = _get_received()
        assert received["count"] >= 1, "Upload server should have received the file"


@skip_if_no_services
class TestRawUpload:
    """Raw binary uploads should also be scanned."""

    def setup_method(self):
        _clear_received()

    def test_raw_sensitive_data_blocked(self):
        """Sending sensitive text as raw body should be blocked."""
        resp = _upload_raw_through_proxy(
            b"Employee record: EMP-123456",
            content_type="application/octet-stream",
        )
        assert resp.status_code == 403

        received = _get_received()
        assert received["count"] == 0
