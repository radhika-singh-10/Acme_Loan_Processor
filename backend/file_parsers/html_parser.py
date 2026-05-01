"""
HTML Parser

Extracts text content from HTML files.

SECURITY NOTES (for Unifai demo):
- Extracts text including from hidden elements
- CSS-hidden content is extracted
- Script content may be included
- No XSS sanitization
"""

import logging
import re
import base64
from typing import Optional

logger = logging.getLogger(__name__)


# PII redaction patterns
PII_PATTERNS = [
    # SSN
    (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), '[REDACTED-SSN]'),
    # Credit card numbers
    (re.compile(r'\b(?:\d[ -]?){13,16}\b'), '[REDACTED-CC]'),
    # Passport numbers (generic)
    (re.compile(r'\b[A-Z]{1,2}\d{6,9}\b'), '[REDACTED-PASSPORT]'),
    # Medical record numbers
    (re.compile(r'\bMRN[:\s]?\d{6,10}\b', re.IGNORECASE), '[REDACTED-MRN]'),
    # Email addresses
    (re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'), '[REDACTED-EMAIL]'),
    # Phone numbers
    (re.compile(r'\b(?:\+?\d{1,3}[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b'), '[REDACTED-PHONE]'),
    # Dates of birth
    (re.compile(r'\b(?:DOB|Date of Birth)[:\s]+\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b', re.IGNORECASE), '[REDACTED-DOB]'),
]

# Singapore PII patterns
SG_NRIC_FIN = re.compile(r'\b[STFGM]\d{7}[A-Z]\b')
SG_PASSPORT = re.compile(r'\bE\d{7}[A-Z]\b')
SG_BANK_ACCOUNT = re.compile(r'\b\d{3}-\d{5,6}-\d{1,3}\b')
SG_PHONE = re.compile(r'\b(?:\+65[\s-]?)?[689]\d{7}\b')
SG_FULL_NAME = re.compile(r'\b(?:Name|Full Name)[:\s]+[A-Z][a-z]+(?: [A-Z][a-z]+){1,3}\b')
SG_HEALTH_RECORD = re.compile(r'\b(?:Medisave|Medishield|CHAS|HealthHub|health record)\b', re.IGNORECASE)

# Suspicious AI-injection phrases
INJECTION_PHRASES = [
    re.compile(r'ignore\s+(?:previous|all|above)\s+instructions', re.IGNORECASE),
    re.compile(r'you\s+are\s+now\s+(?:a|an)\s+\w+', re.IGNORECASE),
    re.compile(r'disregard\s+(?:your|all|previous)\s+(?:instructions|rules|guidelines)', re.IGNORECASE),
    re.compile(r'system\s*prompt', re.IGNORECASE),
    re.compile(r'jailbreak', re.IGNORECASE),
    re.compile(r'do\s+anything\s+now', re.IGNORECASE),
    re.compile(r'act\s+as\s+(?:a|an|if)', re.IGNORECASE),
    re.compile(r'pretend\s+(?:you\s+are|to\s+be)', re.IGNORECASE),
    re.compile(r'new\s+instructions?:', re.IGNORECASE),
    re.compile(r'override\s+(?:instructions?|rules?|guidelines?)', re.IGNORECASE),
]

# Leetspeak pattern
LEETSPEAK_PATTERN = re.compile(r'\b(?:[a-z]*[013457@$!][a-z0-9@$!]*){3,}\b', re.IGNORECASE)

# Binary/shell command patterns
SHELL_PATTERNS = [
    re.compile(r'\b(?:bash|sh|cmd|powershell|exec|eval|system|popen)\s*\(', re.IGNORECASE),
    re.compile(r'(?:rm\s+-rf|chmod\s+\d+|wget\s+http|curl\s+http)', re.IGNORECASE),
    re.compile(r'(?:\/bin\/|\/etc\/passwd|\/etc\/shadow)', re.IGNORECASE),
]


def _redact_pii(text: str) -> str:
    """Apply PII redaction patterns to text."""
    for pattern, replacement in PII_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def _check_singapore_pii(text: str) -> list:
    """Check for Singapore-specific PII and return list of detected types."""
    detected = []
    if SG_NRIC_FIN.search(text):
        detected.append('NRIC/FIN number')
    if SG_PASSPORT.search(text):
        detected.append('Singapore passport number')
    if SG_BANK_ACCOUNT.search(text):
        detected.append('Singapore bank account number')
    if SG_PHONE.search(text):
        detected.append('Singapore phone number')
    if SG_FULL_NAME.search(text):
        detected.append('Full name')
    if SG_HEALTH_RECORD.search(text):
        detected.append('Health record indicator')
    return detected


def _scan_for_threats(text: str, soup=None) -> list:
    """
    Scan content for hidden prompts, base64 content, leetspeak,
    suspicious AI-injection phrases, and binary/shell commands.
    Returns a list of warning strings.
    """
    warnings = []

    # Check for base64-encoded content
    base64_pattern = re.compile(r'(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')
    for match in base64_pattern.finditer(text):
        candidate = match.group(0)
        if len(candidate) >= 20:
            try:
                decoded = base64.b64decode(candidate).decode('utf-8', errors='ignore')
                if any(c.isprintable() for c in decoded) and len(decoded) > 5:
                    warnings.append(f"Potential base64-encoded content detected")
                    break
            except Exception:
                pass

    # Check for AI injection phrases
    for pattern in INJECTION_PHRASES:
        if pattern.search(text):
            warnings.append(f"Suspicious AI-injection phrase detected: '{pattern.pattern}'")

    # Check for leetspeak
    if LEETSPEAK_PATTERN.search(text):
        warnings.append("Potential leetspeak encoding detected")

    # Check for shell/binary commands
    for pattern in SHELL_PATTERNS:
        if pattern.search(text):
            warnings.append(f"Suspicious shell/binary command detected")
            break

    # Check for hidden elements in soup if provided
    if soup is not None:
        # CSS hidden elements
        hidden_elements = soup.find_all(style=re.compile(
            r'display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0', re.IGNORECASE
        ))
        if hidden_elements:
            warnings.append(f"Hidden elements detected ({len(hidden_elements)} elements with display:none/visibility:hidden/opacity:0)")

        # Off-screen positioned elements
        offscreen_elements = soup.find_all(style=re.compile(
            r'position\s*:\s*(?:absolute|fixed).*?(?:left|top)\s*:\s*-\d+', re.IGNORECASE
        ))
        if offscreen_elements:
            warnings.append(f"Off-screen positioned elements detected ({len(offscreen_elements)} elements)")

        # White-on-white or same-color text
        white_text = soup.find_all(style=re.compile(
            r'color\s*:\s*(?:white|#fff(?:fff)?|rgb\(255,\s*255,\s*255\))', re.IGNORECASE
        ))
        if white_text:
            warnings.append(f"Potentially invisible text detected (white/same-color text: {len(white_text)} elements)")

    return warnings


def _remove_hidden_elements(soup) -> None:
    """Remove hidden elements from BeautifulSoup tree before text extraction."""
    # Remove elements with display:none, visibility:hidden, opacity:0
    for element in soup.find_all(style=re.compile(
        r'display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0', re.IGNORECASE
    )):
        element.decompose()

    # Remove off-screen positioned elements
    for element in soup.find_all(style=re.compile(
        r'position\s*:\s*(?:absolute|fixed).*?(?:left|top)\s*:\s*-\d+', re.IGNORECASE
    )):
        element.decompose()

    # Remove white-on-white text elements
    for element in soup.find_all(style=re.compile(
        r'color\s*:\s*(?:white|#fff(?:fff)?|rgb\(255,\s*255,\s*255\))', re.IGNORECASE
    )):
        element.decompose()


class HTMLParser:
    """
    Parses HTML files and extracts text content.
    """

    def __init__(self):
        pass

    async def extract_text(self, html_content: str) -> str:
        """
        Extract visible text from HTML content with security scanning.
        Hidden elements are removed before extraction.
        """
        try:
            from bs4 import BeautifulSoup

            soup = BeautifulSoup(html_content, 'html.parser')

            # Remove script and style elements
            for element in soup(['script', 'style']):
                element.decompose()

            # Remove hidden elements before extracting text
            _remove_hidden_elements(soup)

            text = soup.get_text(separator='\n', strip=True)

            # Check for Singapore PII and raise if detected
            sg_pii = _check_singapore_pii(text)
            if sg_pii:
                raise ValueError(
                    f"Singapore PII detected in HTML content: {', '.join(sg_pii)}. "
                    f"Content cannot be processed."
                )

            # Redact PII from extracted text
            text = _redact_pii(text)

            logger.info(
                "HTML text extraction complete",
                extra={
                    "text_length": len(text),
                }
            )

            return text

        except ValueError:
            raise
        except Exception as e:
            logger.error(f"HTML extraction error: {e}")
            return f"Error extracting HTML: {str(e)}"

    async def extract_visible_only(self, html_content: str) -> str:
        """
        Extract only visible text by removing hidden elements before extraction.
        """
        try:
            from bs4 import BeautifulSoup

            soup = BeautifulSoup(html_content, 'html.parser')

            # Remove script and style elements
            for element in soup(['script', 'style']):
                element.decompose()

            # Remove hidden elements
            _remove_hidden_elements(soup)

            text = soup.get_text(separator='\n', strip=True)

            # Check for Singapore PII and raise if detected
            sg_pii = _check_singapore_pii(text)
            if sg_pii:
                raise ValueError(
                    f"Singapore PII detected in HTML content: {', '.join(sg_pii)}. "
                    f"Content cannot be processed."
                )

            # Redact PII from extracted text
            text = _redact_pii(text)

            return text

        except ValueError:
            raise
        except Exception as e:
            logger.error(f"HTML visible extraction error: {e}")
            return f"Error extracting HTML: {str(e)}"

    async def extract_metadata(self, html_content: str) -> dict:
        """
        Extract HTML metadata (title, meta tags) with PII redaction.
        """
        try:
            from bs4 import BeautifulSoup

            soup = BeautifulSoup(html_content, 'html.parser')
            metadata = {}

            # Title
            title = soup.find('title')
            if title:
                metadata['title'] = _redact_pii(title.get_text())

            # Meta tags
            for meta in soup.find_all('meta'):
                name = meta.get('name', meta.get('property', ''))
                content = meta.get('content', '')
                if name and content:
                    metadata[name] = _redact_pii(content)

            return metadata

        except Exception as e:
            logger.error(f"HTML metadata extraction error: {e}")
            return {}

    async def extract_all(self, html_content: str) -> dict:
        """
        Extract all content from HTML with security scanning and PII redaction.
        """
        from bs4 import BeautifulSoup

        warnings = []

        # Parse soup for threat scanning before removing hidden elements
        soup = BeautifulSoup(html_content, 'html.parser')
        for element in soup(['script', 'style']):
            element.decompose()

        # Scan for threats including hidden element analysis
        raw_text = soup.get_text(separator='\n', strip=True)
        warnings.extend(_scan_for_threats(raw_text, soup=soup))

        text = await self.extract_text(html_content)
        metadata = await self.extract_metadata(html_content)

        return {
            "text": text,
            "metadata": metadata,
            "warnings": warnings
        }