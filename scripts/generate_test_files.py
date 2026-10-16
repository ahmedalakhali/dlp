"""
Test Fixture Generator — creates sample files for DLP testing.

Generates files containing known sensitive patterns (Employee IDs, SSNs,
credit card numbers, confidential keywords) in various formats, plus
one clean control file.

Usage::

    python scripts/generate_test_files.py

Output directory: ``tests/fixtures/``
"""

import csv
import io
import os
import sys
from pathlib import Path

# Ensure the project root is on sys.path so we can run standalone.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
FIXTURES_DIR = PROJECT_ROOT / "tests" / "fixtures"

SENSITIVE_TEXT = "Employee record: EMP-123456, name: John Doe"
SSN_TEXT = "Social Security Number: 123-45-6789"
CC_TEXT = "Payment card: 4111-1111-1111-1111"
KEYWORD_TEXT = "This document is STRICTLY CONFIDENTIAL and must not be shared."
CLEAN_TEXT = (
    "This is a clean document with no sensitive information.\n"
    "It contains only ordinary business text about quarterly reports\n"
    "and team meeting schedules."
)


def _ensure_dir():
    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)


def generate_sensitive_txt():
    """Plain text file with an Employee ID."""
    path = FIXTURES_DIR / "sensitive.txt"
    path.write_text(SENSITIVE_TEXT, encoding="utf-8")
    return path


def generate_sensitive_csv():
    """CSV file with an Employee ID column."""
    path = FIXTURES_DIR / "sensitive.csv"
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["id", "name", "employee_id"])
        writer.writerow(["1", "John Doe", "EMP-123456"])
        writer.writerow(["2", "Jane Smith", "EMP-654321"])
    return path


def generate_sensitive_pdf():
    """PDF containing the Employee ID pattern (uses reportlab)."""
    path = FIXTURES_DIR / "sensitive.pdf"
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas

        c = canvas.Canvas(str(path), pagesize=A4)
        c.setFont("Helvetica", 12)
        c.drawString(72, 700, SENSITIVE_TEXT)
        c.drawString(72, 680, "Department: Engineering")
        c.drawString(72, 660, "Hire Date: 2024-01-15")
        c.save()
    except ImportError:
        print("  WARNING: reportlab not installed — skipping sensitive.pdf")
        return None
    return path


def generate_sensitive_docx():
    """DOCX containing the Employee ID pattern (uses python-docx)."""
    path = FIXTURES_DIR / "sensitive.docx"
    try:
        from docx import Document

        doc = Document()
        doc.add_heading("Employee Record", level=1)
        doc.add_paragraph(SENSITIVE_TEXT)
        doc.add_paragraph("Department: Engineering")
        doc.add_paragraph("Hire Date: 2024-01-15")
        doc.save(str(path))
    except ImportError:
        print("  WARNING: python-docx not installed — skipping sensitive.docx")
        return None
    return path


def generate_sensitive_xlsx():
    """XLSX with a column containing the Employee ID (uses openpyxl)."""
    path = FIXTURES_DIR / "sensitive.xlsx"
    try:
        from openpyxl import Workbook

        wb = Workbook()
        ws = wb.active
        ws.title = "Employees"
        ws.append(["ID", "Name", "Employee ID", "Department"])
        ws.append([1, "John Doe", "EMP-123456", "Engineering"])
        ws.append([2, "Jane Smith", "EMP-654321", "Marketing"])
        wb.save(str(path))
    except ImportError:
        print("  WARNING: openpyxl not installed — skipping sensitive.xlsx")
        return None
    return path


def generate_clean_txt():
    """Plain text file with NO sensitive data."""
    path = FIXTURES_DIR / "clean.txt"
    path.write_text(CLEAN_TEXT, encoding="utf-8")
    return path


def generate_scanned_image():
    """PNG image with 'EMP-123456' rendered as text (for OCR testing)."""
    path = FIXTURES_DIR / "scanned_image.png"
    try:
        from PIL import Image, ImageDraw, ImageFont

        # Create a white image.
        img = Image.new("RGB", (600, 200), color=(255, 255, 255))
        draw = ImageDraw.Draw(img)

        # Try to use a system font, fall back to default.
        try:
            font = ImageFont.truetype("arial.ttf", 28)
        except (IOError, OSError):
            font = ImageFont.load_default()

        draw.text((40, 40), "Employee Record", fill=(0, 0, 0), font=font)
        draw.text((40, 90), "ID: EMP-123456", fill=(0, 0, 0), font=font)
        draw.text((40, 140), "Name: John Doe", fill=(0, 0, 0), font=font)

        img.save(str(path))
    except ImportError:
        print("  WARNING: Pillow not installed — skipping scanned_image.png")
        return None
    return path


def generate_ssn_test():
    """Plain text file with a Social Security Number."""
    path = FIXTURES_DIR / "ssn_test.txt"
    path.write_text(f"Personal information: {SSN_TEXT}", encoding="utf-8")
    return path


def generate_credit_card_test():
    """Plain text file with a credit card number."""
    path = FIXTURES_DIR / "credit_card_test.txt"
    path.write_text(f"Payment details: {CC_TEXT}", encoding="utf-8")
    return path


def generate_keyword_test():
    """Plain text file with confidential keywords."""
    path = FIXTURES_DIR / "keyword_test.txt"
    path.write_text(KEYWORD_TEXT, encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("=" * 60)
    print("  DLP Test Fixture Generator")
    print(f"  Output: {FIXTURES_DIR}")
    print("=" * 60)
    print()

    _ensure_dir()

    generators = [
        ("sensitive.txt",     generate_sensitive_txt),
        ("sensitive.csv",     generate_sensitive_csv),
        ("sensitive.pdf",     generate_sensitive_pdf),
        ("sensitive.docx",    generate_sensitive_docx),
        ("sensitive.xlsx",    generate_sensitive_xlsx),
        ("clean.txt",         generate_clean_txt),
        ("scanned_image.png", generate_scanned_image),
        ("ssn_test.txt",      generate_ssn_test),
        ("credit_card_test.txt", generate_credit_card_test),
        ("keyword_test.txt",  generate_keyword_test),
    ]

    generated = []
    for name, gen_func in generators:
        result = gen_func()
        if result:
            size = result.stat().st_size
            generated.append((name, size))
            print(f"  [+] {name:<25s} ({size:,} bytes)")
        else:
            print(f"  [-] {name:<25s} (skipped)")

    print()
    print(f"Generated {len(generated)} / {len(generators)} fixture files.")
    print()


if __name__ == "__main__":
    main()
