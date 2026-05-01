"""
PDF Parser

Extracts text content from PDF files.

SECURITY NOTES:
- Extracts text with hidden/suspicious content detection
- Scans for prompt injection patterns
- Redacts PII before returning content
- Checks for Singapore-specific PII
"""

import base64
import io
import logging
import re
from typing import Optional

logger = logging.getLogger(__name__)


class PDFParser:
    """
    Parses PDF files and extracts text content.

    Security features:
    - Detects and strips hidden/invisible text indicators
    - Scans for base64-encoded content, leetspeak, shell/binary commands
    - Detects prompt-injection patterns
    - Redacts PII (SSN, passport, credit card, email, phone, DOB, etc.)
    - Blocks uploads containing Singapore PII (NRIC/FIN, etc.)
    """

    # --- PII redaction patterns ---
    PII_PATTERNS = [
        # SSN
        (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), '[REDACTED_SSN]'),
        # Passport numbers (generic: letter(s) + digits)
        (re.compile(r'\b[A-Z]{1,2}\d{6,9}\b'), '[REDACTED_PASSPORT]'),
        # Credit card numbers (13-19 digits, optionally separated by spaces/dashes)
        (re.compile(r'\b(?:\d[ -]?){13,19}\b'), '[REDACTED_CC]'),
        # Medical record numbers (MRN followed by digits)
        (re.compile(r'\bMRN[:\s#]*\d{5,12}\b', re.IGNORECASE), '[REDACTED_MRN]'),
        # Email addresses
        (re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'), '[REDACTED_EMAIL]'),
        # Phone numbers (various formats)
        (re.compile(r'\b(?:\+?\d[\d\s\-().]{7,}\d)\b'), '[REDACTED_PHONE]'),
        # Dates of birth (common formats)
        (re.compile(r'\b(?:DOB|Date of Birth)[:\s]*\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}\b', re.IGNORECASE), '[REDACTED_DOB]'),
    ]

    # --- Singapore PII patterns ---
    SG_PII_PATTERNS = [
        # NRIC/FIN: S/T/F/G followed by 7 digits and a letter
        ('NRIC/FIN', re.compile(r'\b[STFG]\d{7}[A-Z]\b', re.IGNORECASE)),
        # Singapore passport: E followed by 7 digits
        ('SG_PASSPORT', re.compile(r'\bE\d{7}\b')),
        # Singapore bank account numbers (DBS/POSB/OCBC/UOB style: 9-12 digits)
        ('SG_BANK_ACCOUNT', re.compile(r'\b\d{3}-\d{5,6}-\d{1,3}\b')),
        # Singapore phone numbers (+65 prefix or local 8-digit starting with 6/8/9)
        ('SG_PHONE', re.compile(r'\b(?:\+65[\s\-]?)?[689]\d{7}\b')),
        # Medical record indicators
        ('SG_MEDICAL_RECORD', re.compile(r'\b(?:MRN|Medical Record(?:\s+No\.?)?)[:\s#]*\d{5,12}\b', re.IGNORECASE)),
        # Full name patterns (common Singapore name patterns: 2-4 capitalized words)
        ('SG_FULL_NAME', re.compile(r'\b(?:Name|Patient|Customer)[:\s]+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})\b')),
    ]

    # --- Suspicious content patterns ---
    HIDDEN_TEXT_INDICATORS = [
        re.compile(r'(?i)color\s*:\s*white'),
        re.compile(r'(?i)font-size\s*:\s*0'),
        re.compile(r'(?i)visibility\s*:\s*hidden'),
        re.compile(r'(?i)display\s*:\s*none'),
    ]

    PROMPT_INJECTION_PATTERNS = [
        re.compile(r'(?i)ignore\s+(all\s+)?previous\s+instructions?'),
        re.compile(r'(?i)disregard\s+(all\s+)?previous\s+instructions?'),
        re.compile(r'(?i)you\s+are\s+now\s+(?:a\s+)?(?:an?\s+)?(?:different|new|another)'),
        re.compile(r'(?i)system\s*prompt'),
        re.compile(r'(?i)act\s+as\s+(?:a\s+)?(?:an?\s+)?(?:different|new|another|evil|unrestricted)'),
        re.compile(r'(?i)jailbreak'),
        re.compile(r'(?i)do\s+anything\s+now'),
        re.compile(r'(?i)pretend\s+(?:you\s+are|to\s+be)'),
        re.compile(r'(?i)<\s*/?(?:system|prompt|instruction)\s*>'),
    ]

    SHELL_COMMAND_PATTERNS = [
        re.compile(r'(?i)\b(?:bash|sh|cmd|powershell|exec|eval|system|popen)\s*[\(\[]'),
        re.compile(r'(?i)(?:rm\s+-rf|del\s+/[fqs]|format\s+c:)'),
        re.compile(r'(?i)(?:wget|curl)\s+https?://'),
        re.compile(r'(?i)(?:chmod|chown|sudo|su\s+root)'),
        re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]'),  # binary/control chars
    ]

    LEETSPEAK_PATTERN = re.compile(
        r'(?i)\b(?:[a-z0-9]*(?:(?:3(?=e)|4(?=a)|1(?=i|l)|0(?=o)|5(?=s)|7(?=t))[a-z0-9]*){3,})\b'
    )

    def __init__(self):
        pass

    def _redact_pii(self, text: str) -> str:
        """Redact common PII categories from text."""
        for pattern, replacement in self.PII_PATTERNS:
            text = pattern.sub(replacement, text)
        return text

    def _scan_for_suspicious_content(self, text: str) -> list:
        """
        Scan text for hidden/invisible text indicators, base64-encoded content,
        leetspeak, shell/binary commands, and prompt-injection patterns.
        Returns a list of warning strings.
        """
        warnings = []

        # Check for hidden text indicators
        for pattern in self.HIDDEN_TEXT_INDICATORS:
            if pattern.search(text):
                warnings.append(f"Hidden text indicator detected: {pattern.pattern}")

        # Check for base64-encoded content
        b64_pattern = re.compile(r'(?:[A-Za-z0-9+/]{40,}={0,2})')
        b64_matches = b64_pattern.findall(text)
        if b64_matches:
            warnings.append(f"Possible base64-encoded content detected ({len(b64_matches)} occurrence(s))")

        # Check for prompt injection patterns
        for pattern in self.PROMPT_INJECTION_PATTERNS:
            if pattern.search(text):
                warnings.append(f"Prompt injection pattern detected: {pattern.pattern}")

        # Check for shell/binary commands
        for pattern in self.SHELL_COMMAND_PATTERNS:
            if pattern.search(text):
                warnings.append(f"Shell/binary command pattern detected: {pattern.pattern}")

        # Check for leetspeak
        if self.LEETSPEAK_PATTERN.search(text):
            warnings.append("Leetspeak content detected")

        return warnings

    def _strip_suspicious_content(self, text: str) -> str:
        """Strip or redact flagged suspicious content from text."""
        # Remove base64-encoded blobs
        text = re.sub(r'(?:[A-Za-z0-9+/]{40,}={0,2})', '[REDACTED_BASE64]', text)

        # Redact prompt injection attempts
        for pattern in self.PROMPT_INJECTION_PATTERNS:
            text = pattern.sub('[REDACTED_INJECTION]', text)

        # Redact shell/binary commands
        for pattern in self.SHELL_COMMAND_PATTERNS:
            text = pattern.sub('[REDACTED_COMMAND]', text)

        # Remove binary/control characters
        text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]', '', text)

        return text

    def _scan_for_singapore_pii(self, text: str) -> list:
        """
        Scan text for Singapore-specific PII.
        Returns a list of detected PII type names.
        """
        detected = []
        for pii_type, pattern in self.SG_PII_PATTERNS:
            if pattern.search(text):
                detected.append(pii_type)
        return detected

    async def extract_text(self, pdf_bytes: bytes) -> str:
        """
        Extract all text from a PDF file.

        Applies suspicious content detection, PII redaction, and
        Singapore PII blocking before returning text.
        """
        try:
            from PyPDF2 import PdfReader

            pdf_file = io.BytesIO(pdf_bytes)
            reader = PdfReader(pdf_file)

            text_parts = []
            for page_num, page in enumerate(reader.pages):
                page_text = page.extract_text()
                if page_text:
                    text_parts.append(page_text)

                    logger.debug(
                        f"Extracted text from page {page_num + 1}",
                        extra={
                            "page": page_num + 1,
                            "text_length": len(page_text),
                        }
                    )

            full_text = '\n\n'.join(text_parts)

            # Scan for suspicious content and strip it
            suspicious_warnings = self._scan_for_suspicious_content(full_text)
            if suspicious_warnings:
                for warning in suspicious_warnings:
                    logger.warning(f"Suspicious content in PDF: {warning}")
                full_text = self._strip_suspicious_content(full_text)

            # Redact PII
            full_text = self._redact_pii(full_text)

            # Scan for Singapore PII and block if found
            sg_pii_found = self._scan_for_singapore_pii(full_text)
            if sg_pii_found:
                logger.warning(
                    f"Singapore PII detected in PDF upload: {sg_pii_found}"
                )
                raise ValueError(
                    f"Upload blocked: Singapore PII detected in PDF content: {', '.join(sg_pii_found)}"
                )

            logger.info(
                "PDF text extraction complete",
                extra={
                    "total_pages": len(reader.pages),
                    "total_text_length": len(full_text)
                }
            )

            return full_text

        except ValueError:
            raise
        except Exception as e:
            logger.error(f"PDF extraction error: {e}")
            return f"Error extracting PDF: {str(e)}"

    async def extract_metadata(self, pdf_bytes: bytes) -> dict:
        """
        Extract PDF metadata.
        """
        try:
            from PyPDF2 import PdfReader

            pdf_file = io.BytesIO(pdf_bytes)
            reader = PdfReader(pdf_file)

            metadata = {}
            if reader.metadata:
                for key in reader.metadata:
                    metadata[key] = reader.metadata[key]

            return metadata

        except Exception as e:
            logger.error(f"PDF metadata extraction error: {e}")
            return {}

    async def extract_all(self, pdf_bytes: bytes) -> dict:
        """
        Extract all content from PDF with security analysis.
        """
        warnings = []

        try:
            text = await self.extract_text(pdf_bytes)
        except ValueError as e:
            # Singapore PII detected — surface in warnings and re-raise
            warnings.append(str(e))
            raise

        metadata = await self.extract_metadata(pdf_bytes)

        # Re-scan the (already sanitized) text for any remaining warnings to surface
        suspicious_warnings = self._scan_for_suspicious_content(text)
        warnings.extend(suspicious_warnings)

        # Check for Singapore PII types in the sanitized text (informational)
        sg_pii_found = self._scan_for_singapore_pii(text)
        if sg_pii_found:
            warnings.append(f"Singapore PII types detected: {', '.join(sg_pii_found)}")

        return {
            "text": text,
            "metadata": metadata,
            "warnings": warnings
        }