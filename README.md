# DLP Web Upload Prevention

An enterprise Data Loss Prevention system that intercepts, inspects, and blocks
sensitive file uploads through managed browsers.

## Architecture

```
Browser → mitmproxy (intercept) → Policy Service (FastAPI) → Scanner Pipeline
                                        ├── Apache Tika (text extraction)
                                        ├── Presidio (pattern matching)
                                        └── Tesseract OCR (scanned docs)
```

## Quick Start

### Prerequisites
- Python 3.11+
- Docker Desktop (for Tika Server)
- Tesseract OCR installed and on PATH

### Setup
```powershell
.\scripts\setup.ps1
```

### Start All Services
```powershell
.\scripts\start_all.ps1
```

### Run Tests
```powershell
python -m pytest tests/ -v
```

## Project Structure

| Directory | Purpose |
|-----------|---------|
| `config/` | Policy rules, proxy settings, logging config |
| `proxy/` | mitmproxy add-on and multipart parser |
| `scanner/` | Tika extractor, Presidio analyzer, OCR, pipeline |
| `policy/` | FastAPI service, data models, audit logging |
| `tests/` | Unit, integration, and end-to-end tests |
| `scripts/` | Setup, start/stop, test fixtures |

## Configuration

Edit `config/policies.yaml` to define your sensitive data rules:
- **Regex patterns**: Employee IDs, SSNs, custom formats
- **Keywords**: "STRICTLY CONFIDENTIAL", "INTERNAL ONLY"
- **Built-in Presidio entities**: Credit cards, emails, phone numbers
