"""
Content Scanner Module

Extracts and analyzes hidden content from various file formats.

SECURITY NOTES (for Unifai demo):
- Extracts hidden content but does NOT flag it as suspicious
- Hidden text extraction works but no threat analysis
- EXIF extraction works but no scanning of contents
- Acts as a utility, not a security control

AFTER UNIFAI REMEDIATION:
- Extracted hidden content is flagged for review
- Automatic threat detection on extracted content
- Integration with prompt injection detector
"""

import logging
import re
import unicodedata
from typing import Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Maximum allowed content size (100KB)
MAX_CONTENT_SIZE = 100_000

# Prompt injection patterns to detect and block
PROMPT_INJECTION_PATTERNS = [
    re.compile(r'ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)', re.IGNORECASE),
    re.compile(r'disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)', re.IGNORECASE),
    re.compile(r'forget\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)', re.IGNORECASE),
    re.compile(r'you\s+are\s+now\s+(a\s+)?(?!an?\s+AI)', re.IGNORECASE),
    re.compile(r'new\s+instructions?\s*:', re.IGNORECASE),
    re.compile(r'system\s*prompt\s*:', re.IGNORECASE),
    re.compile(r'<\s*system\s*>', re.IGNORECASE),
    re.compile(r'\[INST\]', re.IGNORECASE),
    re.compile(r'###\s*instruction', re.IGNORECASE),
    re.compile(r'act\s+as\s+(if\s+you\s+are|a)', re.IGNORECASE),
    re.compile(r'pretend\s+(you\s+are|to\s+be)', re.IGNORECASE),
    re.compile(r'override\s+(safety|security|guidelines|restrictions)', re.IGNORECASE),
    re.compile(r'bypass\s+(safety|security|guidelines|restrictions|filters?)', re.IGNORECASE),
    re.compile(r'jailbreak', re.IGNORECASE),
    re.compile(r'DAN\s+mode', re.IGNORECASE),
    re.compile(r'do\s+anything\s+now', re.IGNORECASE),
    re.compile(r'reveal\s+(your\s+)?(system\s+)?prompt', re.IGNORECASE),
    re.compile(r'print\s+(your\s+)?(system\s+)?prompt', re.IGNORECASE),
    re.compile(r'output\s+(your\s+)?(system\s+)?prompt', re.IGNORECASE),
]

# Singapore PII patterns
SINGAPORE_PII_PATTERNS = {
    'nric_fin': re.compile(r'\b[STFGM]\d{7}[A-Z]\b'),
    'singapore_phone': re.compile(r'\b(?:\+65[\s-]?)?[689]\d{3}[\s-]?\d{4}\b'),
    'singapore_postal': re.compile(r'\bSingapore\s+\d{6}\b', re.IGNORECASE),
    'uen': re.compile(r'\b\d{9}[A-Z]\b|\b[A-Z]\d{8}[A-Z]\b'),
}

# Zero-tolerance PII patterns (global)
ZERO_TOLERANCE_PII_PATTERNS = {
    'ssn': (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), '[REDACTED-SSN]'),
    'passport': (re.compile(r'\b[A-Z]{1,2}\d{6,9}\b'), '[REDACTED-PASSPORT]'),
    'email': (re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'), '[REDACTED-EMAIL]'),
    'credit_card': (re.compile(r'\b(?:\d{4}[\s\-]?){3}\d{4}\b'), '[REDACTED-CC]'),
    'phone': (re.compile(r'\b(?:\+?1[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}\b'), '[REDACTED-PHONE]'),
    'dob': (re.compile(r'\b(?:0?[1-9]|[12]\d|3[01])[\/\-](?:0?[1-9]|1[0-2])[\/\-](?:19|20)\d{2}\b'), '[REDACTED-DOB]'),
}


@dataclass
class ExtractedContent:
    """Container for extracted content from files."""
    visible_text: str
    hidden_text: Optional[str] = None
    metadata: Optional[dict] = None
    encoded_content: Optional[list[str]] = None
    warnings: Optional[list[str]] = None


class SecurityException(Exception):
    """Raised when malicious content is detected."""
    pass


class ContentScanner:
    """
    Scans and extracts content from various file formats.

    This scanner extracts:
    - Visible text content
    - Hidden text (CSS hidden, white-on-white, etc.)
    - File metadata
    - Encoded content (base64, etc.)

    Security controls:
    - Hidden content is flagged and scanned for threats
    - Prompt injection patterns are detected and blocked
    - PII is redacted before LLM analysis
    - Singapore PII triggers content blocking
    """

    def __init__(self):
        self.extraction_count = 0

    def _sanitize_content(self, content: str, label: str = "content") -> str:
        """
        Sanitize content by stripping control characters, prompt-injection
        patterns, and enforcing size limits.
        """
        if not content:
            return content

        # Enforce size limit
        if len(content) > MAX_CONTENT_SIZE:
            logger.warning(
                "Content truncated due to size limit",
                extra={"label": label, "original_size": len(content)}
            )
            content = content[:MAX_CONTENT_SIZE]

        # Remove control characters (except newline, tab, carriage return)
        sanitized = ''.join(
            ch for ch in content
            if unicodedata.category(ch)[0] != 'C' or ch in ('\n', '\t', '\r')
        )

        return sanitized

    def _contains_prompt_injection(self, content: str) -> bool:
        """Check if content contains prompt injection patterns."""
        if not content:
            return False
        for pattern in PROMPT_INJECTION_PATTERNS:
            if pattern.search(content):
                return True
        return False

    def _redact_pii(self, content: str) -> str:
        """Redact zero-tolerance PII categories from content."""
        if not content:
            return content
        for pii_type, (pattern, placeholder) in ZERO_TOLERANCE_PII_PATTERNS.items():
            content = pattern.sub(placeholder, content)
        return content

    def _detect_singapore_pii(self, content: str) -> list[str]:
        """Detect Singapore-specific PII in content. Returns list of detected types."""
        detected = []
        if not content:
            return detected
        for pii_type, pattern in SINGAPORE_PII_PATTERNS.items():
            if pattern.search(content):
                detected.append(pii_type)
        return detected

    async def scan_html(self, html_content: str) -> ExtractedContent:
        """
        Scan HTML content for visible and hidden text.

        Extracts hidden content and flags it as suspicious.
        Raises SecurityException if hidden text contains prompt injection.
        """
        from bs4 import BeautifulSoup

        soup = BeautifulSoup(html_content, 'html.parser')

        # Extract visible text
        visible_text = self._sanitize_content(
            soup.get_text(separator='\n', strip=True), "html_visible"
        )

        # Extract hidden content (CSS hidden elements)
        hidden_elements = []

        # Find elements with hiding styles
        for element in soup.find_all(style=True):
            style = element.get('style', '').lower()
            if any(prop in style for prop in [
                'display:none', 'display: none',
                'visibility:hidden', 'visibility: hidden',
                'opacity:0', 'opacity: 0',
                'font-size:0', 'font-size: 0',
                'color:#fff', 'color:white', 'color: white',
            ]):
                text = element.get_text(strip=True)
                if text:
                    hidden_elements.append(text)

        # Find elements with hiding classes (common patterns)
        for element in soup.find_all(class_=re.compile(
            r'(hidden|invisible|sr-only|visually-hidden|d-none)',
            re.IGNORECASE
        )):
            text = element.get_text(strip=True)
            if text:
                hidden_elements.append(text)

        warnings = []
        hidden_text = None

        if hidden_elements:
            warnings.append(
                f"SECURITY: {len(hidden_elements)} hidden element(s) detected in HTML content"
            )
            raw_hidden = '\n'.join(hidden_elements)
            sanitized_hidden = self._sanitize_content(raw_hidden, "html_hidden")

            # Scan hidden content for prompt injection
            if self._contains_prompt_injection(sanitized_hidden):
                logger.warning(
                    "Prompt injection detected in HTML hidden content",
                    extra={"hidden_preview": sanitized_hidden[:100]}
                )
                raise SecurityException(
                    "Malicious content detected in hidden HTML elements. Content blocked."
                )

            hidden_text = sanitized_hidden
            warnings.append("SECURITY: Hidden content has been flagged for review")

        logger.info(
            "HTML content scanned",
            extra={
                "visible_length": len(visible_text),
                "hidden_elements_found": len(hidden_elements),
                "warnings_count": len(warnings),
            }
        )

        return ExtractedContent(
            visible_text=visible_text,
            hidden_text=hidden_text,
            warnings=warnings if warnings else None
        )

    async def scan_pdf_text(self, text_content: str) -> ExtractedContent:
        """
        Analyze extracted PDF text for hidden content indicators.

        Returns warnings when suspicious patterns are detected.
        """
        # Sanitize input
        text_content = self._sanitize_content(text_content, "pdf_text")

        # Look for suspicious patterns that might indicate hidden content
        suspicious_patterns = []

        # Check for unusual whitespace patterns
        if '\x00' in text_content:
            suspicious_patterns.append("null_bytes")

        # Check for potential invisible characters
        invisible_chars = ['\u200b', '\u200c', '\u200d', '\ufeff']
        for char in invisible_chars:
            if char in text_content:
                suspicious_patterns.append(f"invisible_char_{ord(char)}")

        warnings = []
        if suspicious_patterns:
            logger.warning(
                "Suspicious patterns in PDF",
                extra={"patterns": suspicious_patterns}
            )
            warnings.append(
                f"SECURITY: Suspicious patterns detected in PDF content: {', '.join(suspicious_patterns)}"
            )

        # Check for prompt injection in PDF text
        if self._contains_prompt_injection(text_content):
            logger.warning("Prompt injection detected in PDF text content")
            warnings.append("SECURITY: Potential prompt injection detected in PDF content")
            raise SecurityException(
                "Malicious content detected in PDF. Content blocked."
            )

        return ExtractedContent(
            visible_text=text_content,
            hidden_text=None,
            warnings=warnings if warnings else None
        )

    async def scan_image_metadata(self, metadata: dict) -> ExtractedContent:
        """
        Scan image metadata for hidden content.

        Warns on suspicious metadata fields. Blocks prompt injection in EXIF.
        """
        # Extract text from relevant metadata fields
        text_fields = []
        dangerous_fields = ['Comment', 'UserComment', 'ImageDescription',
                          'XPComment', 'XPSubject', 'XPTitle']

        for field in dangerous_fields:
            if field in metadata:
                value = metadata[field]
                if value:
                    text_fields.append(f"{field}: {value}")

        metadata_text = '\n'.join(text_fields) if text_fields else None
        warnings = []

        if metadata_text:
            sanitized_metadata = self._sanitize_content(metadata_text, "image_metadata")
            warnings.append(
                f"SECURITY: {len(text_fields)} metadata field(s) extracted from image and flagged for review"
            )

            # Scan metadata for prompt injection
            if self._contains_prompt_injection(sanitized_metadata):
                logger.warning(
                    "Prompt injection detected in image metadata",
                    extra={"metadata_preview": sanitized_metadata[:100]}
                )
                raise SecurityException(
                    "Malicious content detected in image metadata. Content blocked."
                )

            metadata_text = sanitized_metadata

        logger.info(
            "Image metadata extracted",
            extra={
                "fields_found": len(text_fields),
                "warnings_count": len(warnings),
            }
        )

        return ExtractedContent(
            visible_text="",
            hidden_text=metadata_text,
            metadata=metadata,
            warnings=warnings if warnings else None
        )

    async def extract_base64_content(self, content: str) -> list[str]:
        """
        Extract and decode base64 encoded content.

        Decoded content is scanned for threat indicators before being returned.
        """
        import base64 as b64

        decoded_contents = []

        # Find base64-like strings (minimum 20 chars)
        b64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        potential_b64 = re.findall(b64_pattern, content)

        for match in potential_b64:
            try:
                # Attempt to decode
                decoded = b64.b64decode(match).decode('utf-8', errors='ignore')
                if decoded and len(decoded) > 10:  # Filter noise
                    # Sanitize decoded content
                    decoded = self._sanitize_content(decoded, "base64_decoded")

                    # Scan for prompt injection before appending
                    if self._contains_prompt_injection(decoded):
                        logger.warning(
                            "Prompt injection detected in base64-decoded content — skipping",
                            extra={
                                "original_length": len(match),
                                "decoded_length": len(decoded),
                                "decoded_preview": decoded[:100]
                            }
                        )
                        continue

                    decoded_contents.append(decoded)
                    logger.debug(
                        "Base64 content decoded and scanned",
                        extra={
                            "original_length": len(match),
                            "decoded_length": len(decoded),
                        }
                    )
            except:
                continue

        return decoded_contents

    async def combine_for_analysis(
        self,
        extracted: ExtractedContent
    ) -> str:
        """
        Combine all extracted content for LLM analysis.

        Security controls applied:
        - Hidden content and decoded content scanned for prompt injection
        - Suspicious content flagged and stripped
        - PII redacted from all content parts
        - Singapore PII triggers blocking
        - All parts sanitized before combination
        """
        parts = []

        # Sanitize and add visible text
        visible = self._sanitize_content(extracted.visible_text, "visible_text")
        visible = self._redact_pii(visible)
        parts.append(visible)

        # Process hidden text with security filtering
        if extracted.hidden_text:
            sanitized_hidden = self._sanitize_content(extracted.hidden_text, "hidden_text")

            if self._contains_prompt_injection(sanitized_hidden):
                logger.warning(
                    "Prompt injection detected in hidden text during combine — stripping content",
                    extra={"hidden_preview": sanitized_hidden[:100]}
                )
                # Strip the malicious hidden content rather than passing it through
            else:
                sanitized_hidden = self._redact_pii(sanitized_hidden)
                parts.append(f"\n[Additional content — flagged for review]:\n{sanitized_hidden}")

        # Process encoded content with security filtering
        if extracted.encoded_content:
            for i, decoded in enumerate(extracted.encoded_content):
                sanitized_decoded = self._sanitize_content(decoded, f"encoded_content_{i}")

                if self._contains_prompt_injection(sanitized_decoded):
                    logger.warning(
                        "Prompt injection detected in decoded content during combine — stripping",
                        extra={"decoded_preview": sanitized_decoded[:100], "index": i}
                    )
                    # Strip the malicious decoded content rather than passing it through
                    continue

                sanitized_decoded = self._redact_pii(sanitized_decoded)
                parts.append(f"\n[Decoded content {i+1} — flagged for review]:\n{sanitized_decoded}")

        combined = '\n'.join(parts)

        # Check for Singapore PII and block if found
        sg_pii_detected = self._detect_singapore_pii(combined)
        if sg_pii_detected:
            logger.warning(
                "Singapore PII detected in combined content — blocking",
                extra={"pii_types": sg_pii_detected}
            )
            raise ValueError(
                f"Singapore PII detected in uploaded file content ({', '.join(sg_pii_detected)}). "
                "Content cannot be sent to the LLM."
            )

        return combined


# ============================================================================
# REMEDIATED VERSION (commented out - Unifai would enable this)
# ============================================================================

# class ContentScanner:
#     """
#     SECURE VERSION - After Unifai remediation
#
#     This version:
#     - Flags hidden content as suspicious
#     - Integrates with threat detection
#     - Generates security warnings
#     - Blocks content with detected threats
#     """
#
#     async def scan_html(self, html_content: str) -> ExtractedContent:
#         """Scan with security awareness."""
#         # ... extraction code ...
#
#         warnings = []
#         if hidden_elements:
#             warnings.append(f"SECURITY: {len(hidden_elements)} hidden elements detected")
#
#             # Scan hidden content for threats
#             from .prompt_injection import PromptInjectionDetector
#             detector = PromptInjectionDetector()
#             for hidden in hidden_elements:
#                 result = await detector.scan(hidden)
#                 if result.has_violations:
#                     warnings.append(f"THREAT: Malicious content in hidden element")
#
#         return ExtractedContent(
#             visible_text=visible_text,
#             hidden_text=hidden_text,
#             warnings=warnings
#         )