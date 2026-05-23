"""
PDF Parser

Extracts text content from PDF files.
"""

import io
import re
import logging
from typing import Optional

logger = logging.getLogger(__name__)


def _redact_pii(text: str) -> str:
    """Redact common PII patterns from text."""
    if not text:
        return text

    # SSNs (US)
    text = re.sub(r'\b\d{3}-\d{2}-\d{4}\b', '[REDACTED-SSN]', text)

    # Credit card numbers
    text = re.sub(r'\b(?:\d[ -]?){13,16}\b', '[REDACTED-CC]', text)

    # Passport numbers (generic alphanumeric)
    text = re.sub(r'\b[A-Z]{1,2}\d{6,9}\b', '[REDACTED-PASSPORT]', text)

    # Email addresses
    text = re.sub(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b', '[REDACTED-EMAIL]', text)

    # Phone numbers
    text = re.sub(r'\b(?:\+?\d[\d\s\-().]{7,}\d)\b', '[REDACTED-PHONE]', text)

    return text


def _detect_singapore_pii(text: str) -> list:
    """Detect Singapore-specific PII in text and return list of findings."""
    findings = []
    if not text:
        return findings

    # NRIC/FIN numbers (S/T/F/G followed by 7 digits and a letter)
    if re.search(r'\b[STFG]\d{7}[A-Z]\b', text, re.IGNORECASE):
        findings.append("Singapore NRIC/FIN number detected")

    # Singapore passport numbers
    if re.search(r'\bE\d{7}[A-Z]\b', text, re.IGNORECASE):
        findings.append("Singapore passport number detected")

    # Singapore bank account numbers (various formats)
    if re.search(r'\b\d{3}-\d{5,6}-\d{1,3}\b', text):
        findings.append("Singapore bank account number detected")

    # Singapore phone numbers (+65 followed by 8 digits)
    if re.search(r'(?:\+65[\s-]?)?\b[689]\d{7}\b', text):
        findings.append("Singapore phone number detected")

    # Full name patterns (common Singapore name patterns - simplified heuristic)
    if re.search(r'\b(?:Mr|Mrs|Ms|Dr|Prof)\.?\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3}\b', text):
        findings.append("Possible full name detected")

    return findings


def _detect_suspicious_content(text: str) -> list:
    """Detect suspicious patterns that may indicate prompt injection or malicious content."""
    warnings = []
    if not text:
        return warnings

    # Base64-encoded content
    if re.search(r'(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?', text):
        warnings.append("Possible base64-encoded content detected")

    # Prompt injection keywords
    injection_patterns = [
        r'\bignore\s+(?:previous|prior|above|all)\s+instructions?\b',
        r'\bforget\s+(?:previous|prior|above|all)\s+instructions?\b',
        r'\byou\s+are\s+now\b',
        r'\bact\s+as\b',
        r'\bpretend\s+(?:you\s+are|to\s+be)\b',
        r'\bsystem\s*prompt\b',
        r'\bnew\s+instructions?\b',
        r'\boverride\s+(?:instructions?|rules?|policies?)\b',
        r'\bdisregard\s+(?:previous|prior|above|all)\b',
        r'\bjailbreak\b',
        r'\bDAN\b',
    ]
    for pattern in injection_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            warnings.append(f"Possible prompt injection pattern detected")
            break

    # Shell/binary commands
    shell_patterns = [
        r'\b(?:bash|sh|cmd|powershell|exec|eval|system|popen)\s*[\(\[]',
        r'(?:rm\s+-rf|del\s+/f|format\s+c:)',
        r'(?:wget|curl)\s+https?://',
        r'\b(?:chmod|chown|sudo|su)\s+',
    ]
    for pattern in shell_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            warnings.append("Possible shell/binary command detected")
            break

    # Leetspeak patterns
    if re.search(r'(?:[a-z]\d[a-z]|\d[a-z]\d){2,}', text, re.IGNORECASE):
        warnings.append("Possible leetspeak content detected")

    return warnings


def _sanitize_text(text: str) -> str:
    """Sanitize extracted text by removing or neutralizing suspicious patterns."""
    if not text:
        return text

    # Remove null bytes and control characters (except newlines and tabs)
    text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)

    # Neutralize prompt injection attempts
    injection_patterns = [
        (r'\bignore\s+(?:previous|prior|above|all)\s+instructions?\b', '[FILTERED]'),
        (r'\bforget\s+(?:previous|prior|above|all)\s+instructions?\b', '[FILTERED]'),
        (r'\boverride\s+(?:instructions?|rules?|policies?)\b', '[FILTERED]'),
        (r'\bdisregard\s+(?:previous|prior|above|all)\b', '[FILTERED]'),
        (r'\bjailbreak\b', '[FILTERED]'),
    ]
    for pattern, replacement in injection_patterns:
        text = re.sub(pattern, replacement, text, flags=re.IGNORECASE)

    return text


class PDFParser:
    """
    Parses PDF files and extracts text content with security controls.
    """

    def __init__(self):
        pass

    async def extract_text(self, pdf_bytes: bytes) -> str:
        """
        Extract all text from a PDF file with content sanitization and PII redaction.
        """
        try:
            from PyPDF2 import PdfReader

            pdf_file = io.BytesIO(pdf_bytes)
            reader = PdfReader(pdf_file)

            text_parts = []
            for page_num, page in enumerate(reader.pages):
                page_text = page.extract_text()
                if page_text:
                    suspicious_warnings = _detect_suspicious_content(page_text)
                    if suspicious_warnings:
                        for warning in suspicious_warnings:
                            logger.warning(
                                f"Suspicious content on page {page_num + 1}: {warning}"
                            )

                    page_text = _sanitize_text(page_text)
                    page_text = _redact_pii(page_text)
                    text_parts.append(page_text)

                    logger.debug(
                        f"Extracted text from page {page_num + 1}",
                        extra={
                            "page": page_num + 1,
                            "text_length": len(page_text),
                        }
                    )

            full_text = '\n\n'.join(text_parts)

            logger.info(
                "PDF text extraction complete",
                extra={
                    "total_pages": len(reader.pages),
                    "total_text_length": len(full_text)
                }
            )

            return full_text

        except Exception as e:
            logger.error(f"PDF extraction error: {e}")
            return f"Error extracting PDF: {str(e)}"

    async def extract_metadata(self, pdf_bytes: bytes) -> dict:
        """
        Extract PDF metadata with PII redaction.
        """
        try:
            from PyPDF2 import PdfReader

            pdf_file = io.BytesIO(pdf_bytes)
            reader = PdfReader(pdf_file)

            metadata = {}
            if reader.metadata:
                for key in reader.metadata:
                    value = reader.metadata[key]
                    if isinstance(value, str):
                        value = _redact_pii(value)
                    metadata[key] = value

            return metadata

        except Exception as e:
            logger.error(f"PDF metadata extraction error: {e}")
            return {}

    async def extract_all(self, pdf_bytes: bytes) -> dict:
        """
        Extract all content from PDF with security analysis and PII redaction.
        """
        text = await self.extract_text(pdf_bytes)
        metadata = await self.extract_metadata(pdf_bytes)

        warnings = []

        # Detect suspicious/malicious content
        suspicious_warnings = _detect_suspicious_content(text)
        warnings.extend(suspicious_warnings)

        # Detect Singapore PII in text
        sg_pii_findings = _detect_singapore_pii(text)
        warnings.extend(sg_pii_findings)

        # Detect Singapore PII in metadata values
        for key, value in metadata.items():
            if isinstance(value, str):
                sg_meta_findings = _detect_singapore_pii(value)
                for finding in sg_meta_findings:
                    warnings.append(f"Metadata field '{key}': {finding}")

        return {
            "text": text,
            "metadata": metadata,
            "warnings": warnings
        }