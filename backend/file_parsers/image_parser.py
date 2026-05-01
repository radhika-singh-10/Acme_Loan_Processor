"""
Image Parser

Extracts content from image files including EXIF metadata.

SECURITY NOTES:
- EXIF metadata extracted with security scanning
- Comments and descriptions scanned for prompt injections
- PII redaction applied to all text fields
- GPS/location data stripped
- Singapore PII detection enforced
"""

import io
import logging
import re
import unicodedata
from typing import Optional

logger = logging.getLogger(__name__)

# GPS-related EXIF tag IDs to strip entirely
GPS_TAG_IDS = {
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
    19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
    34853,  # GPSInfo
}

# Maximum length for any single metadata text field
MAX_FIELD_LENGTH = 500

# Prompt injection trigger phrases
INJECTION_TRIGGER_PHRASES = [
    r'ignore\s+(previous|prior|above|all)\s+(instructions?|prompts?|context)',
    r'disregard\s+(previous|prior|above|all)\s+(instructions?|prompts?|context)',
    r'forget\s+(previous|prior|above|all)\s+(instructions?|prompts?|context)',
    r'you\s+are\s+now\s+',
    r'act\s+as\s+(a\s+)?(?:different|new|another)',
    r'new\s+instructions?\s*:',
    r'system\s*:\s*',
    r'<\s*system\s*>',
    r'\[system\]',
    r'assistant\s*:\s*',
    r'human\s*:\s*',
    r'user\s*:\s*',
    r'jailbreak',
    r'prompt\s+injection',
    r'override\s+(safety|security|policy|guidelines?)',
    r'bypass\s+(safety|security|policy|filter)',
    r'do\s+anything\s+now',
    r'dan\s+mode',
    r'developer\s+mode',
    r'sudo\s+',
    r'rm\s+-rf',
    r'exec\s*\(',
    r'eval\s*\(',
    r'__import__',
    r'subprocess',
    r'os\.system',
    r'shell\s*=\s*True',
]

INJECTION_PATTERN = re.compile(
    '|'.join(INJECTION_TRIGGER_PHRASES),
    re.IGNORECASE | re.DOTALL
)

# Base64 blob pattern (long base64 strings)
BASE64_BLOB_PATTERN = re.compile(r'[A-Za-z0-9+/]{60,}={0,2}')

# Shell/binary command patterns
SHELL_COMMAND_PATTERN = re.compile(
    r'(?:bash|sh|cmd|powershell|python|perl|ruby|php|curl|wget|nc|ncat|netcat)\s*[\-\/]',
    re.IGNORECASE
)

# PII patterns
PHONE_PATTERN = re.compile(
    r'(?:\+?\d[\d\s\-().]{7,}\d)',
)
EMAIL_PATTERN = re.compile(
    r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'
)
# Singapore NRIC/FIN
SG_NRIC_PATTERN = re.compile(
    r'\b[STFGM]\d{7}[A-Z]\b'
)
# Singapore phone numbers
SG_PHONE_PATTERN = re.compile(
    r'(?:\+65[\s\-]?)?\b[689]\d{3}[\s\-]?\d{4}\b'
)
# Singapore postal code
SG_POSTAL_PATTERN = re.compile(
    r'\bSingapore\s+\d{6}\b|\b\d{6}\b(?=\s*,?\s*Singapore)',
    re.IGNORECASE
)
# Credit card numbers
CC_PATTERN = re.compile(
    r'\b(?:\d[ \-]?){13,16}\b'
)
# GPS coordinates
GPS_COORD_PATTERN = re.compile(
    r'\b\d{1,3}\.\d{4,}\s*[NS]?\s*,?\s*\d{1,3}\.\d{4,}\s*[EW]?\b'
)
# Biometric hints
BIOMETRIC_PATTERN = re.compile(
    r'\b(?:fingerprint|retina|iris|facial\s+recognition|biometric|face\s+id|thumbprint)\b',
    re.IGNORECASE
)
# Home address patterns (basic)
ADDRESS_PATTERN = re.compile(
    r'\b\d+\s+[A-Za-z\s]{3,30}(?:street|st|avenue|ave|road|rd|boulevard|blvd|lane|ln|drive|dr|court|ct|place|pl|way)\b',
    re.IGNORECASE
)

# Singapore PII detection patterns (for blocking)
SG_PII_PATTERNS = [
    SG_NRIC_PATTERN,
    SG_PHONE_PATTERN,
    SG_POSTAL_PATTERN,
]


class SingaporePIIDetectedError(Exception):
    """Raised when Singapore PII is detected in image metadata."""
    pass


class ImageParser:
    """
    Parses image files and extracts metadata.

    Security controls applied:
    - EXIF text fields scanned for prompt injection
    - PII redacted from all text values
    - GPS/location tags stripped entirely
    - Singapore PII detection enforced
    - Length limits enforced on all text fields
    - Full metadata preview removed from logs
    """

    def __init__(self):
        pass

    def _redact_pii(self, value: str) -> str:
        """
        Redact PII patterns from a string value.
        Covers phone numbers, emails, GPS coordinates, biometric hints,
        addresses, credit card numbers, and Singapore-specific PII.
        """
        if not isinstance(value, str):
            return value

        # Redact Singapore NRIC/FIN
        value = SG_NRIC_PATTERN.sub('[REDACTED-NRIC]', value)
        # Redact Singapore phone numbers
        value = SG_PHONE_PATTERN.sub('[REDACTED-PHONE]', value)
        # Redact Singapore postal codes
        value = SG_POSTAL_PATTERN.sub('[REDACTED-POSTAL]', value)
        # Redact general email addresses
        value = EMAIL_PATTERN.sub('[REDACTED-EMAIL]', value)
        # Redact general phone numbers
        value = PHONE_PATTERN.sub('[REDACTED-PHONE]', value)
        # Redact GPS coordinates
        value = GPS_COORD_PATTERN.sub('[REDACTED-GPS]', value)
        # Redact biometric hints
        value = BIOMETRIC_PATTERN.sub('[REDACTED-BIOMETRIC]', value)
        # Redact home addresses
        value = ADDRESS_PATTERN.sub('[REDACTED-ADDRESS]', value)
        # Redact credit card numbers
        value = CC_PATTERN.sub('[REDACTED-CC]', value)

        return value

    def _sanitize_metadata_value(self, value: str) -> Optional[str]:
        """
        Sanitize a metadata text value by:
        1. Stripping invisible/control characters
        2. Checking for prompt injection patterns
        3. Checking for base64 blobs
        4. Checking for shell/binary commands
        5. Enforcing length limits
        6. Redacting PII

        Returns sanitized string, or None if the value should be rejected.
        """
        if not isinstance(value, str):
            return None

        # Strip control characters and invisible Unicode characters
        cleaned = []
        for ch in value:
            cat = unicodedata.category(ch)
            # Allow printable characters; strip control chars (Cc), format chars (Cf), etc.
            if cat.startswith('C') and ch not in ('\n', '\r', '\t'):
                continue
            cleaned.append(ch)
        value = ''.join(cleaned).strip()

        if not value:
            return None

        # Enforce length limit
        if len(value) > MAX_FIELD_LENGTH:
            value = value[:MAX_FIELD_LENGTH]

        # Check for prompt injection trigger phrases
        if INJECTION_PATTERN.search(value):
            logger.warning("Prompt injection pattern detected in EXIF field; field rejected.")
            return None

        # Check for base64 blobs (potential hidden payloads)
        if BASE64_BLOB_PATTERN.search(value):
            logger.warning("Base64 blob detected in EXIF field; field rejected.")
            return None

        # Check for shell/binary commands
        if SHELL_COMMAND_PATTERN.search(value):
            logger.warning("Shell command pattern detected in EXIF field; field rejected.")
            return None

        # Redact PII
        value = self._redact_pii(value)

        return value

    def _detect_singapore_pii(self, text: str) -> bool:
        """
        Detect Singapore-specific PII in a text string.
        Returns True if Singapore PII is found.
        """
        if not isinstance(text, str):
            return False
        for pattern in SG_PII_PATTERNS:
            if pattern.search(text):
                return True
        return False

    async def extract_metadata(self, image_bytes: bytes) -> dict:
        """
        Extract EXIF and other metadata from image.
        GPS tags are stripped. All text values are PII-redacted.
        """
        try:
            from PIL import Image
            from PIL.ExifTags import TAGS

            image = Image.open(io.BytesIO(image_bytes))
            metadata = {}

            # Get basic image info
            metadata['format'] = image.format
            metadata['size'] = image.size
            metadata['mode'] = image.mode

            # Extract EXIF data with GPS stripping and PII redaction
            exif_data = image._getexif()
            if exif_data:
                for tag_id, value in exif_data.items():
                    # Strip GPS tags entirely to prevent fine-location leakage
                    if tag_id in GPS_TAG_IDS:
                        continue

                    tag = TAGS.get(tag_id, tag_id)

                    # Convert bytes to string for JSON serialization
                    if isinstance(value, bytes):
                        try:
                            value = value.decode('utf-8', errors='ignore')
                        except Exception:
                            value = str(value)

                    # Redact PII from string values before storing
                    if isinstance(value, str):
                        value = self._redact_pii(value)

                    metadata[tag] = value

            # Log without full metadata preview to avoid leaking unsanitized content
            logger.info(
                "Image metadata extracted",
                extra={
                    "format": image.format,
                    "size": image.size,
                    "exif_fields": len(metadata),
                }
            )

            return metadata

        except Exception as e:
            logger.error(f"Image metadata extraction error: {e}")
            return {"error": str(e)}

    async def extract_text_fields(self, metadata: dict) -> str:
        """
        Extract text from relevant metadata fields.
        Each field is scanned for prompt injection and PII before use.
        """
        text_fields = []

        # Fields that commonly contain text content
        dangerous_fields = [
            'ImageDescription',
            'XPComment',
            'XPSubject',
            'XPTitle',
            'XPKeywords',
            'UserComment',
            'Comment',
            'Artist',
            'Copyright',
            'Software',
        ]

        for field in dangerous_fields:
            if field in metadata:
                value = metadata[field]
                if value and isinstance(value, str):
                    # Sanitize: strip injection patterns, control chars, enforce length, redact PII
                    sanitized = self._sanitize_metadata_value(value)
                    if sanitized is None:
                        logger.warning(
                            f"Field '{field}' rejected after sanitization.",
                            extra={"field": field}
                        )
                        continue

                    # Additional PII redaction pass
                    sanitized = self._redact_pii(sanitized)

                    text_fields.append(f"{field}: {sanitized}")
                    logger.debug(
                        f"Found text in {field}",
                        extra={"field": field}
                    )

        return '\n'.join(text_fields)

    async def extract_all(self, image_bytes: bytes) -> str:
        """
        Extract all content from image for analysis.
        Applies sanitization, PII redaction, and Singapore PII detection
        before returning content.
        """
        metadata = await self.extract_metadata(image_bytes)
        text_content = await self.extract_text_fields(metadata)

        # Singapore PII detection: scan combined text content
        combined_for_scan = text_content
        if self._detect_singapore_pii(combined_for_scan):
            logger.error(
                "Singapore PII detected in image metadata; blocking content.",
                extra={"action": "blocked"}
            )
            raise SingaporePIIDetectedError(
                "Singapore PII detected in image metadata. Content blocked to prevent PII leakage."
            )

        result_parts = []

        if text_content:
            result_parts.append(f"Image Metadata:\n{text_content}")

        result_parts.append(
            f"Image Info: {metadata.get('format', 'unknown')} {metadata.get('size', 'unknown')}"
        )

        return '\n\n'.join(result_parts)