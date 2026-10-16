"""
Tesseract OCR Integration — extracts text from images and scanned documents.

Uses pytesseract as the Python wrapper around the Tesseract OCR engine.
Falls back gracefully if Tesseract is not installed.
"""

import io
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Lazy-import pytesseract to avoid hard failure if not installed
_pytesseract = None
_PIL_Image = None
_tesseract_available: bool | None = None


def _ensure_imports() -> bool:
    """Lazy-import pytesseract and Pillow, returning True if available."""
    global _pytesseract, _PIL_Image, _tesseract_available

    if _tesseract_available is not None:
        return _tesseract_available

    try:
        import pytesseract
        from PIL import Image

        # Quick check: does the tesseract binary exist?
        pytesseract.get_tesseract_version()

        _pytesseract = pytesseract
        _PIL_Image = Image
        _tesseract_available = True
        logger.info("Tesseract OCR is available: %s", pytesseract.get_tesseract_version())
    except Exception as exc:
        _tesseract_available = False
        logger.warning("Tesseract OCR not available: %s", exc)

    return _tesseract_available


@dataclass
class OCRResult:
    """Result of OCR text extraction."""
    text: str
    language: str
    success: bool
    error: str = ""


def is_available() -> bool:
    """Return True if Tesseract OCR is installed and usable."""
    return _ensure_imports()


def extract_text_from_image(
    image_bytes: bytes,
    languages: list[str] | None = None,
) -> OCRResult:
    """
    Run OCR on an image and return extracted text.

    Args:
        image_bytes: Raw image content (PNG, JPEG, TIFF, BMP).
        languages:   Tesseract language codes, e.g. ["eng"].
                     Defaults to ["eng"].

    Returns:
        OCRResult with extracted text.
    """
    if not _ensure_imports():
        return OCRResult(
            text="",
            language="",
            success=False,
            error="Tesseract OCR is not installed or not on PATH",
        )

    if languages is None:
        languages = ["eng"]

    lang_str = "+".join(languages)

    try:
        image = _PIL_Image.open(io.BytesIO(image_bytes))
        text = _pytesseract.image_to_string(image, lang=lang_str)
        return OCRResult(
            text=text.strip(),
            language=lang_str,
            success=True,
        )
    except Exception as exc:
        logger.error("OCR extraction failed: %s", exc)
        return OCRResult(
            text="",
            language=lang_str,
            success=False,
            error=str(exc),
        )


# ---------------------------------------------------------------------------
# Image-type detection helper
# ---------------------------------------------------------------------------
IMAGE_MIME_TYPES = frozenset({
    "image/png",
    "image/jpeg",
    "image/tiff",
    "image/bmp",
    "image/gif",
    "image/webp",
})


def is_image_type(mime_type: str) -> bool:
    """Return True if the MIME type is an image that Tesseract can process."""
    return mime_type.lower() in IMAGE_MIME_TYPES
