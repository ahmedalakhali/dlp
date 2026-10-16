# DLP Web Upload Prevention

An enterprise Data Loss Prevention system that intercepts, inspects, and blocks
sensitive file uploads through managed browsers.

## Architecture

```
Browser → mitmproxy (intercept) → Policy Service (FastAPI) → Scanner Pipeline
                                        ├── Apache Tika (text extraction + direct UTF-8 fallback)
                                        ├── Microsoft Presidio (PII & pattern matching)
                                        └── Tesseract OCR (scanned docs & images)
```

## Key Capabilities

- **Multipart Form Uploads**: Standard browser forms (`multipart/form-data`) such as file-sharing portals.
- **Direct Cloud Storage Uploads**: Intercepts modern Single Page App (SPA) direct `PUT` uploads (e.g. ChatGPT, AWS S3 presigned URLs, Azure Blob Storage) with raw document MIME types (`text/plain`, `application/pdf`, Office docs).
- **HTTPS/TLS Decryption**: Transparent inspection of outbound TLS connections.
- **Privacy by Design**: Cryptographic hashing (SHA-256) of inspected payloads; sensitive file contents are never stored in audit logs.
- **Robust Bypass Rules**: Excludes banking, identity providers, and background OS update traffic (e.g., Windows Update) to prevent connection pool exhaustion.

---

## Quick Start

### Prerequisites
- Python 3.11 or 3.12
- Docker Desktop (optional, for Apache Tika container; falls back to direct UTF-8 decoding if offline)
- Tesseract OCR (optional, for image OCR)

### Setup
```powershell
.\scripts\setup.ps1
```

### Install HTTPS Root Certificate
To inspect HTTPS uploads without browser warnings, install your locally generated Root CA into the Windows Trusted Root Store:
```powershell
# Install
.\scripts\install_ca.ps1

# To remove later
.\scripts\install_ca.ps1 -Uninstall
```
*(Note: Never commit private CA keys to version control. The script uses your machine's locally generated CA from `~/.mitmproxy/`.)*

### Start All Services
```powershell
.\scripts\start_all.ps1
```
This starts:
1. Apache Tika (port 9998)
2. FastAPI Policy Service (port 8000)
3. DLP Interception Proxy (port 8080)
4. Local Test Upload Server (port 5000)

### Run Tests
```powershell
.\.venv\Scripts\python.exe -m pytest tests/ -v
```

### Stop All Services
```powershell
.\scripts\stop_all.ps1
```

---

## Project Structure

| Directory / File | Purpose |
|------------------|---------|
| `config/` | Policy rules (`policies.yaml`), proxy settings (`proxy_config.yaml`), audit logging |
| `proxy/` | `addon.py` (mitmproxy interception hook) and `multipart_parser.py` (multipart & raw PUT parser) |
| `scanner/` | `extractor.py` (Tika), `analyzer.py` (Presidio + regex), `ocr.py`, `pipeline.py` |
| `policy/` | `service.py` (FastAPI REST API), `models.py`, `rules.py`, `audit.py` (SQLite audit store) |
| `tests/` | 55 unit, integration, and end-to-end tests |
| `scripts/` | `install_ca.ps1`, `start_all.ps1`, `stop_all.ps1`, `setup.ps1`, test fixtures |

---

## Configuration

Edit `config/policies.yaml` to define sensitive data rules:
- **Regex patterns**: Employee IDs (`EMP-\d{6}`), SSNs, custom internal identifiers
- **Keywords**: "STRICTLY CONFIDENTIAL", "INTERNAL ONLY", "RESTRICTED"
- **Built-in Presidio entities**: Credit card numbers, email addresses, phone numbers
