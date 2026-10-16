"""
Test Upload Server — a minimal Flask app that accepts file uploads
and logs exactly what it receives.

This server is the **proof target** for the DLP system:
  • If the DLP blocks correctly → this server receives NOTHING.
  • If the DLP allows correctly → this server receives the file.

Usage::

    python scripts/test_upload_server.py

Endpoints:
    GET  /            — Simple HTML upload form
    POST /upload      — Accept file uploads
    GET  /received    — List all received files (JSON)
    DELETE /received  — Clear all received files
"""

import os
import json
import shutil
from pathlib import Path

from flask import Flask, request, jsonify

app = Flask(__name__)

RECEIVED_DIR = Path(__file__).parent.parent / "received"


def _ensure_received_dir():
    """Create the received/ directory if it doesn't exist."""
    RECEIVED_DIR.mkdir(parents=True, exist_ok=True)


def _save_to_disk(filename: str, content: bytes) -> Path:
    """Save uploaded file content to the received/ directory."""
    _ensure_received_dir()
    # Sanitise filename to avoid path traversal.
    safe_name = Path(filename).name or "unnamed"
    dest = RECEIVED_DIR / safe_name

    # Avoid overwriting: append a counter if the file already exists.
    counter = 1
    original_dest = dest
    while dest.exists():
        dest = original_dest.with_stem(f"{original_dest.stem}_{counter}")
        counter += 1

    dest.write_bytes(content)
    return dest


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/", methods=["GET"])
def index():
    """Serve a simple HTML upload form with proxy connection status."""
    is_proxied = bool(request.headers.get("X-DLP-Proxy"))
    app.logger.info("INDEX REQUEST from %s: is_proxied=%s, X-DLP-Proxy=%r", request.remote_addr, is_proxied, request.headers.get("X-DLP-Proxy"))

    if is_proxied:
        status_banner = """
        <div style="background: #064e3b; border: 1px solid #10b981; padding: 14px; border-radius: 8px; margin-bottom: 20px;">
            <strong style="color: #34d399; font-size: 15px;">🛡️ DLP Proxy Active</strong>
            <p style="margin: 6px 0 0; font-size: 13px; color: #d1fae5;">Your request is routed through the DLP Proxy (Port 8080). All uploads are inspected and enforced.</p>
        </div>
        """
    else:
        status_banner = """
        <div style="background: #450a0a; border: 1px solid #ef4444; padding: 14px; border-radius: 8px; margin-bottom: 20px;">
            <strong style="color: #f87171; font-size: 15px;">⚠️ Direct Connection (Unprotected)</strong>
            <p style="margin: 6px 0 0; font-size: 13px; color: #fee2e2;">Your browser bypassed the DLP proxy because Chromium browsers always ignore proxies for <code>127.0.0.1</code> and <code>localhost</code>.</p>
            <p style="margin: 6px 0 0; font-size: 13px; color: #fca5a5;"><strong>Fix:</strong> Open your browser to your LAN IP instead:<br>
            <a href="http://192.168.1.5:5000" style="color: #93c5fd; font-weight: bold; font-size: 15px;">http://192.168.1.5:5000</a></p>
        </div>
        """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>DLP Test Upload Server</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            max-width: 600px;
            margin: 60px auto;
            background: #1a1a2e;
            color: #e0e0e0;
            padding: 20px;
        }}
        h1 {{ color: #0fbcf9; }}
        form {{
            background: #16213e;
            padding: 24px;
            border-radius: 12px;
            border: 1px solid #0fbcf950;
        }}
        input[type="file"] {{
            display: block;
            margin: 16px 0;
            color: #e0e0e0;
        }}
        button {{
            background: #0fbcf9;
            color: #1a1a2e;
            border: none;
            padding: 10px 24px;
            border-radius: 6px;
            font-size: 16px;
            cursor: pointer;
            font-weight: bold;
        }}
        button:hover {{ background: #00d2ff; }}
        .info {{
            margin-top: 20px;
            padding: 12px;
            background: #0d2137;
            border-radius: 8px;
            font-size: 13px;
        }}
        code {{
            background: #00000080;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: Consolas, monospace;
        }}
    </style>
</head>
<body>
    <h1>📤 DLP Test Upload Server</h1>
    {status_banner}
    <form action="/upload" method="POST" enctype="multipart/form-data">
        <label>Select file(s) to upload:</label>
        <input type="file" name="file" multiple>
        <button type="submit">Upload</button>
    </form>
    <div class="info">
        <strong>Purpose:</strong> This server logs every file it receives.
        When routed through the DLP proxy, sensitive files should
        <em>never</em> appear here.
    </div>
</body>
</html>"""


@app.route("/upload", methods=["POST"])
def upload():
    """Accept uploaded files and log them."""
    files = request.files.getlist("file")
    received = []

    for f in files:
        content = f.read()
        preview = content[:100]
        app.logger.info(
            "RECEIVED: %s, size=%d, content_type=%s, preview=%r",
            f.filename, len(content), f.content_type, preview,
        )
        saved_path = _save_to_disk(f.filename or "unnamed", content)
        received.append({
            "filename": f.filename,
            "size": len(content),
            "saved_as": str(saved_path.name),
        })

    if not files:
        # Handle raw body uploads (application/octet-stream).
        raw = request.get_data()
        if raw:
            app.logger.info("RECEIVED raw upload: size=%d, preview=%r", len(raw), raw[:100])
            saved_path = _save_to_disk("raw-upload", raw)
            received.append({
                "filename": "raw-upload",
                "size": len(raw),
                "saved_as": str(saved_path.name),
            })

    return jsonify({"status": "ok", "received": received}), 200


@app.route("/received", methods=["GET"])
def list_received():
    """List all received files."""
    _ensure_received_dir()
    files = []
    for path in sorted(RECEIVED_DIR.iterdir()):
        if path.is_file():
            files.append({
                "filename": path.name,
                "size": path.stat().st_size,
            })
    return jsonify({"files": files, "count": len(files)}), 200


@app.route("/received", methods=["DELETE"])
def clear_received():
    """Delete all received files."""
    if RECEIVED_DIR.exists():
        shutil.rmtree(RECEIVED_DIR)
    _ensure_received_dir()
    app.logger.info("Cleared all received files")
    return jsonify({"status": "cleared"}), 200


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO)

    print("=" * 60)
    print("  DLP Test Upload Server")
    print("  http://127.0.0.1:5000")
    print("=" * 60)
    print()
    print("  POST /upload     — receive file uploads")
    print("  GET  /received   — list received files")
    print("  DELETE /received — clear received files")
    print()

    _ensure_received_dir()
    app.run(host="0.0.0.0", port=5000, debug=True)

