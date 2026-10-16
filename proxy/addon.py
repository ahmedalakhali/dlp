"""
DLP Mitmproxy Add-on — intercepts outbound file uploads and blocks
uploads that contain sensitive data.

This is the **enforcement point** of the DLP system.  It hooks into
mitmproxy's request lifecycle, extracts files from multipart / raw /
form-encoded bodies, sends them to the Policy Service for scanning,
and either allows the request through or responds with HTTP 403.

Usage::

    mitmdump --listen-host 127.0.0.1 --listen-port 8080 -s proxy/addon.py

Configuration is loaded from ``config/proxy_config.yaml``.
"""

from __future__ import annotations

import base64
import fnmatch
import logging
import sys
from pathlib import Path

# Ensure project root is in sys.path when invoked via mitmdump
_project_root = Path(__file__).resolve().parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

import httpx
import yaml
from mitmproxy import http

from proxy.multipart_parser import extract_uploads

logger = logging.getLogger("dlp.proxy")


# ---------------------------------------------------------------------------
# Configuration loader
# ---------------------------------------------------------------------------

def _load_config(path: str = "config/proxy_config.yaml") -> dict:
    """Load proxy configuration from YAML."""
    config_path = Path(path)
    if not config_path.is_absolute():
        config_path = _project_root / config_path
    if not config_path.exists():
        logger.warning("Proxy config %s not found — using defaults", config_path)
        return {}
    with open(config_path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


# ---------------------------------------------------------------------------
# Add-on class
# ---------------------------------------------------------------------------

class DLPAddon:
    """Mitmproxy add-on that intercepts upload requests and enforces DLP policy.

    On each HTTP request that carries a body (POST, PUT, PATCH), the add-on:

    1. Checks if the destination is on the bypass list.
    2. Parses the body to extract files / text fields.
    3. Sends each extracted item to the Policy Service for scanning.
    4. If **any** item is BLOCKED → returns HTTP 403 to the browser
       (the original request is never forwarded).
    5. If the policy service is unreachable → applies the configured
       ``fail_action`` (default: BLOCK).
    """

    def __init__(self) -> None:
        config = _load_config()

        proxy_cfg = config.get("proxy", {})
        self.policy_url = proxy_cfg.get("policy_service_url", "http://127.0.0.1:8000")
        self.body_limit = proxy_cfg.get("request_body_limit_bytes", 104_857_600)
        self.scan_timeout = proxy_cfg.get("scan_timeout_seconds", 60)
        self.fail_action = proxy_cfg.get("fail_action", "BLOCK")

        bypass_cfg = config.get("bypass", {})
        self.bypass_domains: list[str] = bypass_cfg.get("domains", [])

        logger.info(
            "DLP Proxy Addon initialised — policy_url=%s, fail_action=%s, "
            "bypass=%d domain(s)",
            self.policy_url,
            self.fail_action,
            len(self.bypass_domains),
        )

    # ------------------------------------------------------------------
    # Mitmproxy hook
    # ------------------------------------------------------------------

    def request(self, flow: http.HTTPFlow) -> None:
        """Intercept outbound requests and scan file uploads."""

        # Mark request as passing through DLP proxy for local test server
        if flow.request.port == 5000 or ":5000" in flow.request.host:
            flow.request.headers["X-DLP-Proxy"] = "active"

        # Only inspect methods that carry a body.
        if flow.request.method not in ("POST", "PUT", "PATCH"):
            return

        # Skip if no body.
        if not flow.request.content or len(flow.request.content) == 0:
            return

        # Check bypass list.
        host = flow.request.host
        if self._is_bypassed(host):
            logger.debug("Bypassed domain: %s", host)
            return

        # Enforce body size limit.
        if len(flow.request.content) > self.body_limit:
            logger.warning(
                "Request body too large (%d bytes) — blocking per fail policy",
                len(flow.request.content),
            )
            flow.response = http.Response.make(
                403,
                b"Upload blocked: request body exceeds size limit",
                {"Content-Type": "text/plain"},
            )
            return

        # Extract files from the request body.
        content_type = flow.request.headers.get("content-type", "")
        uploads = extract_uploads(content_type, flow.request.content)

        if not uploads:
            return  # No files to scan — allow through.

        # Scan each extracted file via the Policy Service.
        source_ip = flow.client_conn.peername[0] if flow.client_conn.peername else "unknown"

        for upload in uploads:
            try:
                fname = upload.filename
                if fname == "raw-upload":
                    cd = flow.request.headers.get("content-disposition", "")
                    if "filename=" in cd:
                        from multipart.multipart import parse_options_header
                        _, cd_opts = parse_options_header(cd)
                        if b"filename" in cd_opts:
                            fname = cd_opts[b"filename"].decode("utf-8", errors="replace")
                    if fname == "raw-upload":
                        import urllib.parse
                        p_path = urllib.parse.urlparse(flow.request.url).path
                        base = Path(p_path).name
                        if base and "." in base and not base.endswith((".com", ".net", ".org", ".php", ".html")):
                            fname = base

                ct = upload.content_type
                if ct in ("", "application/octet-stream") and fname:
                    import mimetypes
                    guessed_ct, _ = mimetypes.guess_type(fname)
                    if guessed_ct:
                        ct = guessed_ct

                verdict = self._scan_file(
                    filename=fname,
                    content_type=ct,
                    file_bytes=upload.data,
                    source_ip=source_ip,
                    destination_host=host,
                )

                if verdict.get("action") == "BLOCK":
                    reason = verdict.get("reason", "Policy violation")
                    matched = verdict.get("matched_rules", [])
                    logger.warning(
                        "BLOCKED upload: %s -> %s (%s, rules: %s)",
                        upload.filename, host, reason, matched,
                    )
                    flow.response = http.Response.make(
                        403,
                        f"Upload blocked by DLP policy: {reason}".encode("utf-8"),
                        {"Content-Type": "text/plain"},
                    )
                    return  # Stop scanning further files.

            except Exception as exc:
                logger.error(
                    "Policy service error for %s: %s — applying %s",
                    upload.filename, exc, self.fail_action,
                )
                if self.fail_action == "BLOCK":
                    flow.response = http.Response.make(
                        403,
                        b"Upload blocked: DLP policy service unavailable",
                        {"Content-Type": "text/plain"},
                    )
                    return

        # All files passed — allow the request through.
        logger.debug("All %d file(s) allowed through", len(uploads))

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _is_bypassed(self, host: str) -> bool:
        """Check if a hostname matches any bypass pattern."""
        for pattern in self.bypass_domains:
            if fnmatch.fnmatch(host, pattern):
                return True
        return False

    def _scan_file(
        self,
        filename: str,
        content_type: str,
        file_bytes: bytes,
        source_ip: str,
        destination_host: str,
    ) -> dict:
        """Send a file to the Policy Service for scanning (synchronous).

        mitmproxy's ``request`` hook is synchronous, so we use a sync
        httpx client here.
        """
        file_b64 = base64.b64encode(file_bytes).decode("ascii")

        payload = {
            "filename": filename,
            "content_type": content_type,
            "file_base64": file_b64,
            "source_ip": source_ip,
            "destination_host": destination_host,
        }

        with httpx.Client(timeout=self.scan_timeout, trust_env=False) as client:
            resp = client.post(
                f"{self.policy_url}/api/v1/scan",
                json=payload,
            )
            resp.raise_for_status()
            return resp.json()


# ---------------------------------------------------------------------------
# Mitmproxy entry point
# ---------------------------------------------------------------------------

addons = [DLPAddon()]
