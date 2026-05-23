"""
Content Scanner Module

Extracts and analyzes hidden content from various file formats.

SECURITY NOTES (for Unifai demo):
- Extracts hidden content and flags it as suspicious
- Hidden text extraction includes threat analysis
- EXIF extraction includes scanning of contents
- Acts as both a utility and a security control

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

# Maximum allowed size for any single content fragment (bytes)
MAX_FRAGMENT_SIZE = 50_000

# Prompt injection patterns to strip
INJECTION_PATTERNS = [
    re.compile(r'ignore\s+(all\s+)?(previous|prior|above)\s+instructions?', re.IGNORECASE),
    re.compile(r'disregard\s+(all\s+)?(previous|prior|above)\s+instructions?', re.IGNORECASE),
    re.compile(r'forget\s+(all\s+)?(previous|prior|above)\s+instructions?', re.IGNORECASE),
    re.compile(r'you\s+are\s+now\s+(?:a|an)\s+', re.IGNORECASE),
    re.compile(r'act\s+as\s+(?:a|an)\s+', re.IGNORECASE),
    re.compile(r'pretend\s+(?:you\s+are|to\s+be)\s+', re.IGNORECASE),
    re.compile(r'system\s*:\s*', re.IGNORECASE),
    re.compile(r'<\s*system\s*>', re.IGNORECASE),
    re.compile(r'\[INST\]', re.IGNORECASE),
    re.compile(r'###\s*instruction', re.IGNORECASE),
    re.compile(r'new\s+instructions?\s*:', re.IGNORECASE),
    re.compile(r'override\s+instructions?', re.IGNORECASE),
    re.compile(r'jailbreak', re.IGNORECASE),
    re.compile(r'prompt\s+injection', re.IGNORECASE),
]

# PII patterns (general)
PII_PATTERNS = {
    'ssn': re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
    'credit_card': re.compile(r'\b(?:\d[ -]?){13,16}\b'),
    'email': re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'),
    'phone_us': re.compile(r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'),
    'ipv4': re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
}

# Singapore-specific PII patterns
SG_PII_PATTERNS = {
    'nric_fin': re.compile(r'\b[STFGM]\d{7}[A-Z]\b'),
    'singpass': re.compile(r'\bSingPass\b', re.IGNORECASE),
    'cpf': re.compile(r'\bCPF\s*(?:account|number|no\.?)?\s*:?\s*\d{3,}', re.IGNORECASE),
    'sg_passport': re.compile(r'\bE\d{7}[A-Z]\b'),
    'sg_phone': re.compile(r'\b(?:\+65[-.\s]?)?\d{4}[-.\s]?\d{4}\b'),
    'sg_address': re.compile(
        r'\b(?:Blk|Block|No\.?)\s+\d+[A-Z]?\s+\w[\w\s]+(?:Road|Rd|Street|St|Avenue|Ave|Drive|Dr|Lane|Ln|Way|Crescent|Cres|Place|Pl|Close|Cl)\b',
        re.IGNORECASE
    ),
    'sg_postal': re.compile(r'\bSingapore\s+\d{6}\b', re.IGNORECASE),
}


class SingaporePIIError(ValueError):
    """Raised when Singapore-specific PII is detected in content."""
    pass


@dataclass
class ExtractedContent:
    """Container for extracted content from files."""
    visible_text: str
    hidden_text: Optional[str] = None
    metadata: Optional[dict] = None
    encoded_content: Optional[list[str]] = None
    warnings: Optional[list[str]] = field(default_factory=list)


class ContentScanner:
    """
    Scans and extracts content from various file formats.

    This scanner extracts:
    - Visible text content
    - Hidden text (CSS hidden, white-on-white, etc.)
    - File metadata
    - Encoded content (base64, etc.)

    All extracted content is scanned for threats, prompt injections,
    and PII before being forwarded to the LLM.
    """

    def __init__(self):
        self.extraction_count = 0

    # ------------------------------------------------------------------
    # Security helpers
    # ------------------------------------------------------------------

    def _strip_control_characters(self, text: str) -> str:
        """Remove non-printable / control characters from text."""
        result = []
        for ch in text:
            cat = unicodedata.category(ch)
            # Allow newlines, tabs, and normal printable characters
            if ch in ('\n', '\r', '\t') or cat[0] not in ('C',):
                result.append(ch)
        return ''.join(result)

    def _strip_injection_patterns(self, text: str) -> tuple[str, list[str]]:
        """
        Remove known prompt-injection patterns from text.
        Returns (sanitized_text, list_of_warnings).
        """
        warnings = []
        for pattern in INJECTION_PATTERNS:
            if pattern.search(text):
                warnings.append(
                    f"SECURITY: Prompt injection pattern detected and removed: "
                    f"'{pattern.pattern[:60]}'"
                )
                text = pattern.sub('[REDACTED-INJECTION]', text)
        return text, warnings

    def _enforce_size_limit(self, text: str, label: str) -> tuple[str, list[str]]:
        """Truncate oversized content fragments."""
        warnings = []
        if len(text.encode('utf-8', errors='replace')) > MAX_FRAGMENT_SIZE:
            text = text[:MAX_FRAGMENT_SIZE]
            warnings.append(
                f"SECURITY: {label} exceeded maximum allowed size and was truncated."
            )
        return text, warnings

    def _redact_pii(self, text: str) -> tuple[str, list[str]]:
        """Redact common PII categories from text."""
        warnings = []
        for pii_type, pattern in PII_PATTERNS.items():
            if pattern.search(text):
                warnings.append(f"PII REDACTED: {pii_type} pattern found and redacted.")
                text = pattern.sub(f'[REDACTED-{pii_type.upper()}]', text)
        return text, warnings

    def _check_singapore_pii(self, text: str) -> None:
        """
        Raise SingaporePIIError if Singapore-specific PII is detected.
        """
        for pii_type, pattern in SG_PII_PATTERNS.items():
            if pattern.search(text):
                raise SingaporePIIError(
                    f"Singapore PII detected ({pii_type}) in content. "
                    "Processing blocked to comply with Singapore data protection policy."
                )

    def _sanitize_fragment(self, text: str, label: str) -> tuple[str, list[str]]:
        """
        Full sanitization pipeline for a single content fragment:
        1. Strip control characters
        2. Enforce size limit
        3. Strip prompt-injection patterns
        4. Redact PII
        Returns (sanitized_text, accumulated_warnings).
        """
        all_warnings: list[str] = []

        text = self._strip_control_characters(text)

        text, size_warnings = self._enforce_size_limit(text, label)
        all_warnings.extend(size_warnings)

        text, injection_warnings = self._strip_injection_patterns(text)
        all_warnings.extend(injection_warnings)

        text, pii_warnings = self._redact_pii(text)
        all_warnings.extend(pii_warnings)

        return text, all_warnings

    # ------------------------------------------------------------------
    # Scanning methods
    # ------------------------------------------------------------------

    async def scan_html(self, html_content: str) -> ExtractedContent:
        """
        Scan HTML content for visible and hidden text.
        Hidden content is flagged and sanitized before being returned.
        """
        from bs4 import BeautifulSoup

        soup = BeautifulSoup(html_content, 'html.parser')

        # Extract visible text
        visible_text = soup.get_text(separator='\n', strip=True)

        # Extract hidden content (CSS hidden elements)
        hidden_elements = []
        warnings: list[str] = []

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

        hidden_text: Optional[str] = None
        if hidden_elements:
            warnings.append(
                f"SECURITY: {len(hidden_elements)} hidden element(s) detected in HTML content."
            )
            sanitized_hidden = []
            for raw in hidden_elements:
                sanitized, frag_warnings = self._sanitize_fragment(raw, "hidden HTML element")
                warnings.extend(frag_warnings)
                sanitized_hidden.append(sanitized)
            hidden_text = '\n'.join(sanitized_hidden)

        # Sanitize visible text as well
        visible_text, vis_warnings = self._sanitize_fragment(visible_text, "visible HTML text")
        warnings.extend(vis_warnings)

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
        Suspicious patterns are flagged and content is sanitized.
        """
        suspicious_patterns = []
        warnings: list[str] = []

        # Check for unusual whitespace patterns
        if '\x00' in text_content:
            suspicious_patterns.append("null_bytes")

        # Check for potential invisible characters
        invisible_chars = ['\u200b', '\u200c', '\u200d', '\ufeff']
        for char in invisible_chars:
            if char in text_content:
                suspicious_patterns.append(f"invisible_char_{ord(char)}")

        if suspicious_patterns:
            warnings.append(
                f"SECURITY: Suspicious patterns detected in PDF content: {suspicious_patterns}"
            )
            logger.warning(
                "Suspicious patterns in PDF",
                extra={"patterns": suspicious_patterns}
            )

        # Sanitize the text content
        text_content, san_warnings = self._sanitize_fragment(text_content, "PDF text")
        warnings.extend(san_warnings)

        return ExtractedContent(
            visible_text=text_content,
            hidden_text=None,
            warnings=warnings if warnings else None
        )

    async def scan_image_metadata(self, metadata: dict) -> ExtractedContent:
        """
        Scan image metadata for hidden content.
        EXIF data is extracted and scanned for threats before being returned.
        """
        text_fields = []
        warnings: list[str] = []
        dangerous_fields = ['Comment', 'UserComment', 'ImageDescription',
                          'XPComment', 'XPSubject', 'XPTitle']

        for field in dangerous_fields:
            if field in metadata:
                value = metadata[field]
                if value:
                    text_fields.append(f"{field}: {value}")

        metadata_text: Optional[str] = None
        if text_fields:
            warnings.append(
                f"SECURITY: {len(text_fields)} metadata field(s) with text content detected. "
                "Scanning for threats."
            )
            raw_metadata = '\n'.join(text_fields)
            metadata_text, san_warnings = self._sanitize_fragment(raw_metadata, "image metadata")
            warnings.extend(san_warnings)

        logger.info(
            "Image metadata extracted and scanned",
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
        Decoded content is scanned for threats before being returned.
        """
        import base64 as b64

        decoded_contents = []

        # Find base64-like strings (minimum 20 chars)
        b64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        potential_b64 = re.findall(b64_pattern, content)

        for match in potential_b64:
            try:
                decoded = b64.b64decode(match).decode('utf-8', errors='ignore')
                if decoded and len(decoded) > 10:  # Filter noise
                    # Sanitize decoded content before accepting it
                    sanitized, san_warnings = self._sanitize_fragment(
                        decoded, "base64-decoded content"
                    )
                    if san_warnings:
                        logger.warning(
                            "Threats detected in base64-decoded content",
                            extra={
                                "original_length": len(match),
                                "decoded_length": len(decoded),
                                "warnings": san_warnings,
                            }
                        )
                    else:
                        logger.debug(
                            "Base64 content decoded and scanned",
                            extra={
                                "original_length": len(match),
                                "decoded_length": len(decoded),
                            }
                        )
                    decoded_contents.append(sanitized)
            except:
                continue

        return decoded_contents

    async def combine_for_analysis(
        self,
        extracted: ExtractedContent
    ) -> str:
        """
        Combine all extracted content for LLM analysis.

        All content fragments are sanitized, PII-redacted, and checked
        for Singapore-specific PII before being forwarded to the LLM.
        """
        parts = []
        all_warnings: list[str] = []

        # Sanitize visible text
        visible, vis_warnings = self._sanitize_fragment(
            extracted.visible_text, "visible text"
        )
        all_warnings.extend(vis_warnings)
        parts.append(visible)

        # Sanitize and append hidden text
        if extracted.hidden_text:
            all_warnings.append(
                "SECURITY: Hidden content detected — sanitizing before LLM forwarding."
            )
            sanitized_hidden, hid_warnings = self._sanitize_fragment(
                extracted.hidden_text, "hidden text"
            )
            all_warnings.extend(hid_warnings)
            parts.append(f"\n[Additional content]:\n{sanitized_hidden}")

        # Sanitize and append encoded content
        if extracted.encoded_content:
            for i, decoded in enumerate(extracted.encoded_content):
                all_warnings.append(
                    f"SECURITY: Encoded content fragment {i+1} detected — sanitizing."
                )
                sanitized_decoded, dec_warnings = self._sanitize_fragment(
                    decoded, f"decoded content {i+1}"
                )
                all_warnings.extend(dec_warnings)
                parts.append(f"\n[Decoded content {i+1}]:\n{sanitized_decoded}")

        combined = '\n'.join(parts)

        # Final PII redaction pass over the fully combined content
        combined, final_pii_warnings = self._redact_pii(combined)
        all_warnings.extend(final_pii_warnings)

        # Singapore PII check — raises SingaporePIIError if detected
        self._check_singapore_pii(combined)

        if all_warnings:
            logger.warning(
                "Content security warnings during combine_for_analysis",
                extra={"warnings": all_warnings}
            )

        return combined


# ============================================================================
# REMEDIATED VERSION (active above)
# ============================================================================