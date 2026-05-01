"""
Image Parser

Extracts content from image files including EXIF metadata.

SECURITY NOTES (for Unifai demo):
- EXIF metadata extracted with sanitization and PII redaction
- Comments and descriptions are scanned for prompt injections
- Singapore PII patterns are detected and redacted
"""

import io
import re
import base64
import logging
import unicodedata
from typing import Optional

logger = logging.getLogger(__name__)

# Maximum length for any single EXIF text value
_MAX_TEXT_LENGTH = 500

# EXIF fields that may contain PII and should be redacted or removed
_GPS_FIELDS = {
    'GPSInfo', 'GPSLatitude', 'GPSLongitude', 'GPSAltitude',
    'GPSLatitudeRef', 'GPSLongitudeRef', 'GPSAltitudeRef',
    'GPSTimeStamp', 'GPSDateStamp', 'GPSDestLatitude',
    'GPSDestLongitude', 'GPSImgDirection', 'GPSSpeed',
    'GPSTrack', 'GPSStatus', 'GPSMeasureMode',
}

_PII_BEARING_FIELDS = {
    'Artist', 'Copyright', 'ImageDescription', 'UserComment',
    'XPComment', 'XPSubject', 'XPTitle', 'XPKeywords',
    'XPAuthor', 'Comment',
}

# Singapore-specific PII patterns
_SG_NRIC_PATTERN = re.compile(r'\b[STFGM]\d{7}[A-Z]\b', re.IGNORECASE)
_SG_PHONE_PATTERN = re.compile(r'(\+65[\s-]?)?\b[689]\d{7}\b')
_EMAIL_PATTERN = re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b')
_FULL_NAME_PATTERN = re.compile(r'\b([A-Z][a-z]+ ){1,3}[A-Z][a-z]+\b')

# Prompt injection patterns
_INJECTION_LINE_PREFIXES = re.compile(
    r'^\s*(ignore|system\s*:|assistant\s*:|user\s*:)',
    re.IGNORECASE | re.MULTILINE
)
_INJECTION_PHRASES = re.compile(
    r'(ignore (all |previous |above |prior )?(instructions?|prompts?|rules?|constraints?)|'
    r'you are now|new instructions?|override|disregard|forget (all |previous )?instructions?|'
    r'act as|pretend (you are|to be)|jailbreak|do anything now|dan mode)',
    re.IGNORECASE
)

# Suspicious AI directive patterns
_AI_DIRECTIVE_PATTERN = re.compile(
    r'(prompt\s*:|instruction\s*:|<\s*system\s*>|<\s*user\s*>|<\s*assistant\s*>|'
    r'\[INST\]|\[/INST\]|###\s*(instruction|system|human|assistant))',
    re.IGNORECASE
)

# Shell/binary command patterns
_SHELL_PATTERN = re.compile(
    r'(\b(bash|sh|cmd|powershell|exec|eval|system|popen|subprocess)\b|'
    r'[;&|`$]\s*\w+|\.\./|/etc/passwd|/bin/)',
    re.IGNORECASE
)

# Invisible/control character pattern (keep printable + common whitespace)
_CONTROL_CHAR_PATTERN = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]')

# Base64 detection (long runs of base64 chars)
_BASE64_PATTERN = re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')

# Leetspeak detection (simple heuristic)
_LEETSPEAK_PATTERN = re.compile(r'[013457@$!]{5,}')


class ImageParser:
    """
    Parses image files and extracts metadata.

    Metadata is sanitized, scanned for prompt injections, and PII is redacted
    before content is returned.
    """

    def __init__(self):
        pass

    def _redact_sg_pii(self, text: str) -> str:
        """Redact Singapore-specific PII patterns from a string."""
        text = _SG_NRIC_PATTERN.sub('[NRIC_REDACTED]', text)
        text = _SG_PHONE_PATTERN.sub('[PHONE_REDACTED]', text)
        text = _EMAIL_PATTERN.sub('[EMAIL_REDACTED]', text)
        text = _FULL_NAME_PATTERN.sub('[NAME_REDACTED]', text)
        return text

    def _is_suspicious_content(self, text: str) -> bool:
        """Return True if the text contains suspicious/malicious patterns."""
        if _INJECTION_LINE_PREFIXES.search(text):
            return True
        if _INJECTION_PHRASES.search(text):
            return True
        if _AI_DIRECTIVE_PATTERN.search(text):
            return True
        if _SHELL_PATTERN.search(text):
            return True
        if _BASE64_PATTERN.search(text):
            # Attempt to decode and check for further injection
            try:
                matches = _BASE64_PATTERN.findall(text)
                for m in matches:
                    decoded = base64.b64decode(m + '==').decode('utf-8', errors='ignore')
                    if _INJECTION_PHRASES.search(decoded) or _AI_DIRECTIVE_PATTERN.search(decoded):
                        return True
            except Exception:
                pass
        if _LEETSPEAK_PATTERN.search(text):
            return True
        return False

    def _sanitize_text_value(self, value: str) -> str:
        """
        Sanitize a text value extracted from EXIF metadata.

        - Strips control characters
        - Truncates overly long strings
        - Removes common prompt injection patterns
        - Redacts Singapore PII
        - Removes base64-encoded content, leetspeak, invisible characters,
          shell/binary commands, and suspicious AI-directive patterns
        """
        if not isinstance(value, str):
            return value

        # Remove invisible/control characters
        value = _CONTROL_CHAR_PATTERN.sub('', value)

        # Normalize unicode to remove invisible unicode tricks
        value = unicodedata.normalize('NFKC', value)

        # Truncate
        if len(value) > _MAX_TEXT_LENGTH:
            value = value[:_MAX_TEXT_LENGTH] + '[TRUNCATED]'

        # Check for suspicious content and sanitize line by line
        if self._is_suspicious_content(value):
            lines = value.splitlines()
            clean_lines = []
            for line in lines:
                # Remove lines that start with injection prefixes
                if _INJECTION_LINE_PREFIXES.match(line):
                    continue
                # Remove lines containing injection phrases
                if _INJECTION_PHRASES.search(line):
                    continue
                # Remove lines with AI directives
                if _AI_DIRECTIVE_PATTERN.search(line):
                    continue
                # Remove lines with shell commands
                if _SHELL_PATTERN.search(line):
                    continue
                # Remove base64 blobs from line
                line = _BASE64_PATTERN.sub('[BASE64_REMOVED]', line)
                # Remove leetspeak blobs
                line = _LEETSPEAK_PATTERN.sub('[FILTERED]', line)
                clean_lines.append(line)
            value = '\n'.join(clean_lines)

        # Redact Singapore PII
        value = self._redact_sg_pii(value)

        return value

    async def extract_metadata(self, image_bytes: bytes) -> dict:
        """
        Extract EXIF and other metadata from image.

        Metadata is sanitized and PII is redacted before returning.
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

            # Extract EXIF data with sanitization
            exif_data = image._getexif()
            if exif_data:
                for tag_id, value in exif_data.items():
                    tag = TAGS.get(tag_id, tag_id)

                    # Strip GPS fields entirely (PII/location data)
                    if tag in _GPS_FIELDS:
                        continue

                    # Convert bytes to string for JSON serialization
                    if isinstance(value, bytes):
                        try:
                            value = value.decode('utf-8', errors='ignore')
                        except Exception:
                            value = str(value)

                    # Sanitize string values
                    if isinstance(value, str):
                        value = self._sanitize_text_value(value)

                    metadata[tag] = value

            # Log without full metadata preview
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

        Text fields are sanitized and scanned for prompt injections before use.
        """
        text_fields = []

        # Fields that commonly contain text content
        text_field_names = [
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

        for field in text_field_names:
            if field in metadata:
                value = metadata[field]
                if value and isinstance(value, str):
                    # Sanitize the value before use
                    sanitized_value = self._sanitize_text_value(value)
                    if sanitized_value.strip():
                        text_fields.append(f"{field}: {sanitized_value}")
                        logger.debug(
                            f"Found text in {field}",
                            extra={
                                "field": field,
                            }
                        )

        return '\n'.join(text_fields)

    async def extract_all(self, image_bytes: bytes) -> str:
        """
        Extract all content from image for analysis.

        All metadata is sanitized, PII is redacted, and GPS/location fields
        are stripped before content is assembled and returned.
        """
        metadata = await self.extract_metadata(image_bytes)

        # Redact PII-bearing EXIF fields before assembling output
        redacted_metadata = {}
        for key, value in metadata.items():
            # Skip GPS fields entirely
            if key in _GPS_FIELDS:
                continue
            # Redact PII from known PII-bearing fields
            if key in _PII_BEARING_FIELDS and isinstance(value, str):
                value = self._sanitize_text_value(value)
            redacted_metadata[key] = value

        text_content = await self.extract_text_fields(redacted_metadata)

        result_parts = []

        if text_content:
            result_parts.append(f"Image Metadata:\n{text_content}")

        result_parts.append(
            f"Image Info: {redacted_metadata.get('format', 'unknown')} "
            f"{redacted_metadata.get('size', 'unknown')}"
        )

        return '\n\n'.join(result_parts)