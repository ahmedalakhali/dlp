"""
Comprehensive tests for proxy.multipart_parser.

Covers:
  • multipart/form-data with single file, multiple files, mixed file+text
  • application/octet-stream (raw binary)
  • application/x-www-form-urlencoded (form fields)
  • malformed / empty bodies
  • missing boundary
  • preservation of filenames and content types
"""

import pytest

from proxy.multipart_parser import UploadedFile, extract_uploads


# ---------------------------------------------------------------------------
# Helpers — build well-formed multipart bodies
# ---------------------------------------------------------------------------

BOUNDARY = "----TestBoundary7MA4YWxkTrZu0gW"


def _build_multipart_body(
    parts: list[dict],
    boundary: str = BOUNDARY,
) -> bytes:
    """Construct a ``multipart/form-data`` body from a list of part dicts.

    Each *part* dict may contain:
      - ``name``        (required) — form field name
      - ``filename``    (optional) — makes the part a file upload
      - ``content_type``(optional) — MIME type for the part
      - ``data``        (required) — bytes or str payload
    """
    lines: list[bytes] = []
    for part in parts:
        lines.append(f"--{boundary}".encode())
        disposition = f'Content-Disposition: form-data; name="{part["name"]}"'
        if "filename" in part:
            disposition += f'; filename="{part["filename"]}"'
        lines.append(disposition.encode())
        if "content_type" in part:
            lines.append(f'Content-Type: {part["content_type"]}'.encode())
        lines.append(b"")  # blank line separating headers from body
        data = part["data"]
        if isinstance(data, str):
            data = data.encode("utf-8")
        lines.append(data)
    lines.append(f"--{boundary}--".encode())
    return b"\r\n".join(lines)


def _multipart_ct(boundary: str = BOUNDARY) -> str:
    return f"multipart/form-data; boundary={boundary}"


# ---------------------------------------------------------------------------
# multipart/form-data tests
# ---------------------------------------------------------------------------

class TestMultipartFormData:
    """Tests for multipart/form-data parsing."""

    def test_single_file(self):
        """A body with one file part yields one UploadedFile."""
        body = _build_multipart_body([
            {
                "name": "document",
                "filename": "report.pdf",
                "content_type": "application/pdf",
                "data": b"%PDF-1.4 fake content",
            },
        ])

        result = extract_uploads(_multipart_ct(), body)

        assert len(result) == 1
        assert result[0].filename == "report.pdf"
        assert result[0].content_type == "application/pdf"
        assert result[0].data == b"%PDF-1.4 fake content"

    def test_multiple_files(self):
        """A body with several file parts yields all of them."""
        body = _build_multipart_body([
            {
                "name": "file1",
                "filename": "image.png",
                "content_type": "image/png",
                "data": b"\x89PNG fake",
            },
            {
                "name": "file2",
                "filename": "notes.txt",
                "content_type": "text/plain",
                "data": b"Hello, World!",
            },
        ])

        result = extract_uploads(_multipart_ct(), body)

        assert len(result) == 2
        assert result[0].filename == "image.png"
        assert result[0].content_type == "image/png"
        assert result[0].data == b"\x89PNG fake"
        assert result[1].filename == "notes.txt"
        assert result[1].content_type == "text/plain"
        assert result[1].data == b"Hello, World!"

    def test_file_and_text_fields(self):
        """File parts and plain text fields are both extracted."""
        body = _build_multipart_body([
            {
                "name": "description",
                "data": "Some project description",
            },
            {
                "name": "attachment",
                "filename": "spec.docx",
                "content_type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                "data": b"PK\x03\x04 fake docx",
            },
        ])

        result = extract_uploads(_multipart_ct(), body)

        assert len(result) == 2

        # First part is a text field.
        text_part = result[0]
        assert text_part.filename == "field:description"
        assert text_part.content_type == "text/plain"
        assert text_part.data == b"Some project description"

        # Second part is a file.
        file_part = result[1]
        assert file_part.filename == "spec.docx"
        assert file_part.content_type == (
            "application/vnd.openxmlformats-officedocument"
            ".wordprocessingml.document"
        )

    def test_file_without_content_type_defaults_to_octet_stream(self):
        """A file part missing a Content-Type header defaults to
        ``application/octet-stream``."""
        body = _build_multipart_body([
            {
                "name": "upload",
                "filename": "mystery.bin",
                "data": b"\x00\x01\x02",
            },
        ])

        result = extract_uploads(_multipart_ct(), body)

        assert len(result) == 1
        assert result[0].content_type == "application/octet-stream"

    def test_filenames_preserved(self):
        """Filenames containing spaces and special characters are preserved."""
        body = _build_multipart_body([
            {
                "name": "f",
                "filename": "my file (final) [v2].xlsx",
                "content_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                "data": b"excel bytes",
            },
        ])

        result = extract_uploads(_multipart_ct(), body)

        assert result[0].filename == "my file (final) [v2].xlsx"

    def test_content_type_preserved(self):
        """Custom content types are returned verbatim."""
        body = _build_multipart_body([
            {
                "name": "data",
                "filename": "data.json",
                "content_type": "application/json; charset=utf-8",
                "data": b'{"key": "value"}',
            },
        ])

        result = extract_uploads(_multipart_ct(), body)

        assert result[0].content_type == "application/json; charset=utf-8"


# ---------------------------------------------------------------------------
# application/octet-stream tests
# ---------------------------------------------------------------------------

class TestOctetStream:
    """Tests for application/octet-stream (raw binary) handling."""

    def test_raw_binary_upload(self):
        """Raw binary body is wrapped as a single UploadedFile."""
        raw = b"\x00\x01\x02\xff\xfe binary payload"
        result = extract_uploads("application/octet-stream", raw)

        assert len(result) == 1
        assert result[0].filename == "raw-upload"
        assert result[0].content_type == "application/octet-stream"
        assert result[0].data == raw

    def test_octet_stream_with_extra_params(self):
        """Content-Type with extra parameters is still recognised."""
        raw = b"data"
        result = extract_uploads(
            "application/octet-stream; name=blob.bin", raw
        )

        assert len(result) == 1
        assert result[0].filename == "raw-upload"


# ---------------------------------------------------------------------------
# application/x-www-form-urlencoded tests
# ---------------------------------------------------------------------------

class TestUrlEncoded:
    """Tests for application/x-www-form-urlencoded form field extraction."""

    def test_single_field(self):
        """A single form field is extracted."""
        body = b"username=admin"
        result = extract_uploads(
            "application/x-www-form-urlencoded", body
        )

        assert len(result) == 1
        assert result[0].filename == "field:username"
        assert result[0].content_type == "text/plain"
        assert result[0].data == b"admin"

    def test_multiple_fields(self):
        """Multiple form fields are each extracted as separate uploads."""
        body = b"first_name=John&last_name=Doe&ssn=123-45-6789"
        result = extract_uploads(
            "application/x-www-form-urlencoded", body
        )

        filenames = {u.filename for u in result}
        assert "field:first_name" in filenames
        assert "field:last_name" in filenames
        assert "field:ssn" in filenames

        ssn_parts = [u for u in result if u.filename == "field:ssn"]
        assert ssn_parts[0].data == b"123-45-6789"

    def test_url_encoded_values(self):
        """Percent-encoded values are decoded properly."""
        body = b"message=Hello%20World%21"
        result = extract_uploads(
            "application/x-www-form-urlencoded", body
        )

        assert result[0].data == b"Hello World!"


# ---------------------------------------------------------------------------
# Edge cases and error handling
# ---------------------------------------------------------------------------

class TestEdgeCases:
    """Edge cases: empty bodies, missing boundaries, malformed data."""

    def test_empty_body_returns_empty(self):
        """An empty body returns an empty list."""
        assert extract_uploads("multipart/form-data; boundary=abc", b"") == []

    def test_none_body_returns_empty(self):
        """A None-ish empty bytes body returns an empty list."""
        assert extract_uploads("application/octet-stream", b"") == []

    def test_empty_content_type_returns_empty(self):
        """An empty content type returns an empty list."""
        assert extract_uploads("", b"some data") == []

    def test_missing_boundary_returns_empty(self):
        """multipart/form-data without a boundary returns an empty list."""
        body = b"some data"
        result = extract_uploads("multipart/form-data", body)
        assert result == []

    def test_malformed_multipart_returns_empty(self):
        """Garbage data with a valid content type returns an empty list
        (no crash)."""
        body = b"this is not valid multipart at all"
        result = extract_uploads(
            "multipart/form-data; boundary=XYZ", body
        )
        # Should return empty — no valid parts found.
        assert isinstance(result, list)

    def test_unsupported_content_type_returns_empty(self):
        """An unsupported content type returns an empty list."""
        result = extract_uploads("application/json", b'{"a":1}')
        assert result == []

    def test_uploaded_file_is_dataclass(self):
        """UploadedFile is a proper dataclass with expected fields."""
        uf = UploadedFile(filename="a.txt", content_type="text/plain", data=b"hi")
        assert uf.filename == "a.txt"
        assert uf.content_type == "text/plain"
        assert uf.data == b"hi"
