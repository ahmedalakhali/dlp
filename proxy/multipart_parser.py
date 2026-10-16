"""
Multipart / form-data request body parser for the DLP upload-prevention proxy.

Supports three content-type families:
  • multipart/form-data   – standard browser file uploads
  • application/octet-stream – raw binary uploads (e.g. XHR / fetch blobs)
  • application/x-www-form-urlencoded – plain form fields (may carry pasted
    sensitive text)

Main entry point
-----------------
    extract_uploads(content_type: str, body: bytes) -> list[UploadedFile]
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from urllib.parse import parse_qs

from multipart.multipart import parse_options_header

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public data structure
# ---------------------------------------------------------------------------

@dataclass
class UploadedFile:
    """Represents a single uploaded file (or text field treated as a file)."""

    filename: str
    content_type: str
    data: bytes


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _parse_multipart(content_type: str, body: bytes) -> list[UploadedFile]:
    """Parse a ``multipart/form-data`` body and return extracted uploads.

    File parts (those with a ``filename`` parameter in Content-Disposition)
    are returned with their original filename and content type.  Regular text
    form fields are wrapped as ``UploadedFile`` objects with a synthetic
    ``field:<name>`` filename and ``text/plain`` content type.

    Parameters
    ----------
    content_type:
        The full Content-Type header value, including the boundary parameter.
    body:
        The raw request body bytes.

    Returns
    -------
    list[UploadedFile]
        Extracted file parts and text fields.
    """
    uploads: list[UploadedFile] = []

    try:
        # Extract the boundary from the Content-Type header.
        _, options = parse_options_header(content_type)
        boundary = options.get(b"boundary")
        if boundary is None:
            logger.warning("Multipart Content-Type missing boundary parameter")
            return []

        if isinstance(boundary, str):
            boundary = boundary.encode("latin-1")

        # Use a simple manual split-based approach that is robust and
        # easy to reason about.  The python-multipart streaming parser is
        # powerful but overly complex for our needs (we already have the
        # whole body in memory).
        delimiter = b"--" + boundary
        # Split the body on the boundary delimiter.
        parts = body.split(delimiter)

        # First element is the preamble (usually empty), last element is
        # the epilogue after the closing "--" marker.  We skip both.
        if len(parts) < 3:
            # Need at least preamble + one part + epilogue
            logger.debug("Multipart body has no parts (boundary split < 3)")
            return []

        for raw_part in parts[1:-1]:
            # Strip the leading CRLF and check for closing marker.
            if raw_part.startswith(b"--"):
                # Closing boundary
                continue

            # Remove optional leading CRLF after boundary line.
            if raw_part.startswith(b"\r\n"):
                raw_part = raw_part[2:]
            elif raw_part.startswith(b"\n"):
                raw_part = raw_part[1:]

            # Split headers from body (separated by blank line).
            header_end = raw_part.find(b"\r\n\r\n")
            if header_end == -1:
                header_end = raw_part.find(b"\n\n")
                if header_end == -1:
                    continue
                header_block = raw_part[:header_end]
                part_body = raw_part[header_end + 2:]
            else:
                header_block = raw_part[:header_end]
                part_body = raw_part[header_end + 4:]

            # Remove trailing CRLF that belongs to the boundary line.
            if part_body.endswith(b"\r\n"):
                part_body = part_body[:-2]
            elif part_body.endswith(b"\n"):
                part_body = part_body[:-1]

            # Parse part headers.
            headers: dict[str, str] = {}
            for line in header_block.split(b"\r\n") if b"\r\n" in header_block else header_block.split(b"\n"):
                if b":" in line:
                    key, _, value = line.partition(b":")
                    headers[key.strip().lower().decode("latin-1")] = value.strip().decode("latin-1")

            disposition = headers.get("content-disposition", "")
            part_ct = headers.get("content-type", "")

            # Extract name and filename from Content-Disposition.
            field_name = _extract_header_param(disposition, "name")
            file_name = _extract_header_param(disposition, "filename")

            if file_name is not None:
                # This is a file upload part.
                uploads.append(UploadedFile(
                    filename=file_name,
                    content_type=part_ct if part_ct else "application/octet-stream",
                    data=part_body,
                ))
            else:
                # This is a regular form text field.
                name = field_name if field_name else "unknown"
                uploads.append(UploadedFile(
                    filename=f"field:{name}",
                    content_type="text/plain",
                    data=part_body,
                ))

    except Exception:
        logger.exception("Failed to parse multipart/form-data body")
        return []

    return uploads


def _extract_header_param(header_value: str, param_name: str) -> str | None:
    """Extract a named parameter from a header value string.

    Example::

        >>> _extract_header_param('form-data; name="file"; filename="report.pdf"', "filename")
        'report.pdf'
    """
    # Simple parser: look for param_name="value" or param_name=value
    lower = header_value.lower()
    search = f"{param_name}="
    idx = lower.find(search)
    if idx == -1:
        return None

    start = idx + len(search)
    rest = header_value[start:]
    if rest.startswith('"'):
        # Quoted value
        end = rest.find('"', 1)
        if end == -1:
            return rest[1:]
        return rest[1:end]
    else:
        # Unquoted – take until ';' or end
        end = rest.find(";")
        if end == -1:
            return rest.strip()
        return rest[:end].strip()


def _parse_octet_stream(body: bytes) -> list[UploadedFile]:
    """Wrap a raw binary body as a single :class:`UploadedFile`.

    Parameters
    ----------
    body:
        The raw request body bytes.

    Returns
    -------
    list[UploadedFile]
    """
    return [UploadedFile(
        filename="raw-upload",
        content_type="application/octet-stream",
        data=body,
    )]


def _parse_urlencoded(body: bytes) -> list[UploadedFile]:
    """Parse ``application/x-www-form-urlencoded`` form data.

    Each field value is returned as an :class:`UploadedFile` with a synthetic
    ``field:<fieldname>`` filename and ``text/plain`` content type.

    Parameters
    ----------
    body:
        The raw request body bytes.

    Returns
    -------
    list[UploadedFile]
    """
    uploads: list[UploadedFile] = []
    try:
        decoded = body.decode("utf-8", errors="replace")
        parsed = parse_qs(decoded, keep_blank_values=True)
        for field_name, values in parsed.items():
            for value in values:
                uploads.append(UploadedFile(
                    filename=f"field:{field_name}",
                    content_type="text/plain",
                    data=value.encode("utf-8"),
                ))
    except Exception:
        logger.exception("Failed to parse application/x-www-form-urlencoded body")
        return []

    return uploads


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_uploads(content_type: str, body: bytes) -> list[UploadedFile]:
    """Extract uploaded files / form fields from an HTTP request body.

    Dispatches to the appropriate parser based on the Content-Type header.
    Returns an empty list for unsupported or malformed content.

    Parameters
    ----------
    content_type:
        The Content-Type header value (e.g.
        ``"multipart/form-data; boundary=----WebKitFormBoundary..."``).
    body:
        The raw request body bytes.

    Returns
    -------
    list[UploadedFile]
        A list of extracted uploads.  May be empty if the content type is
        unsupported, the body is empty, or parsing fails.
    """
    if not content_type or not body:
        logger.debug("Empty content_type or body — returning no uploads")
        return []

    ct_lower = content_type.lower().strip()

    if ct_lower.startswith("multipart/form-data"):
        return _parse_multipart(content_type, body)

    if ct_lower.startswith("application/octet-stream"):
        return _parse_octet_stream(body)

    if ct_lower.startswith("application/x-www-form-urlencoded"):
        return _parse_urlencoded(body)

    # Raw document / image uploads (e.g. direct-to-cloud PUT/POST like ChatGPT / S3 / Azure)
    if ct_lower.startswith((
        "text/",
        "application/pdf",
        "application/msword",
        "application/vnd.openxmlformats-officedocument",
        "application/vnd.ms-excel",
        "application/vnd.ms-powerpoint",
        "image/",
    )):
        clean_ct = content_type.split(";")[0].strip()
        return [UploadedFile(
            filename="raw-upload",
            content_type=clean_ct,
            data=body,
        )]

    logger.debug("Unsupported content type for upload extraction: %s", content_type)
    return []
