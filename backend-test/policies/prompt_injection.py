"""
Prompt Injection Detection Module

Detects malicious/hidden prompts in content that could manipulate LLM behavior.

SECURITY NOTES (for Unifai demo):
- scan() method is a NO-OP - returns no threats
- Hidden text detection not implemented
- Base64/encoded content not decoded
- Unicode homoglyph attacks not detected

AFTER UNIFAI REMEDIATION:
- Detect hidden text (white-on-white, zero-size, off-page)
- Decode and scan base64 content
- Detect unicode homoglyph attacks
- Identify known prompt injection patterns
"""

import logging
import re
import base64
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class ThreatMatch:
    """Represents a detected threat."""
    threat_type: str
    severity: str  # low, medium, high, critical
    description: str
    content_preview: str
    location: str


@dataclass
class ThreatDetectionResult:
    """Result of threat detection scan."""
    has_violations: bool
    threats: list[ThreatMatch] = field(default_factory=list)
    scanned_content_length: int = 0

    def to_dict(self) -> dict:
        return {
            "has_violations": self.has_violations,
            "threats": [
                {
                    "type": t.threat_type,
                    "severity": t.severity,
                    "description": t.description,
                    "preview": t.content_preview[:50] + "..." if len(t.content_preview) > 50 else t.content_preview,
                    "location": t.location
                }
                for t in self.threats
            ],
            "scanned_content_length": self.scanned_content_length
        }


class PromptInjectionDetector:
    """
    Detects prompt injection and hidden malicious content.

    Threat Categories:
    - hidden_text: Invisible/hidden text in documents
    - encoded_content: Base64 or otherwise encoded malicious content
    - prompt_injection: Direct prompt injection attempts
    - unicode_attack: Homoglyph or unicode-based attacks
    - metadata_injection: Malicious content in file metadata
    """

    # Known prompt injection patterns
    INJECTION_PATTERNS = [
        r"ignore\s+(previous|all|above)\s+instructions?",
        r"disregard\s+(previous|all|above)\s+(instructions?|context)",
        r"new\s+instructions?:",
        r"system\s*:\s*you\s+are",
        r"admin\s+override",
        r"developer\s+mode",
        r"jailbreak",
        r"\[INST\]",
        r"<\|im_start\|>",
        r"###\s*(instruction|system|human|assistant)",
    ]

    # Unicode homoglyphs that could be used for attacks
    HOMOGLYPH_MAP = {
        'а': 'a',  # Cyrillic
        'е': 'e',
        'о': 'o',
        'р': 'p',
        'с': 'c',
        'х': 'x',
        # Add more as needed
    }

    # Zero-width and bidi override characters
    ZERO_WIDTH_CHARS = [
        '\u200b',  # Zero-width space
        '\u200c',  # Zero-width non-joiner
        '\u200d',  # Zero-width joiner
        '\u2060',  # Word joiner
        '\ufeff',  # Zero-width no-break space (BOM)
        '\u00ad',  # Soft hyphen
    ]

    BIDI_OVERRIDE_CHARS = [
        '\u202a',  # Left-to-right embedding
        '\u202b',  # Right-to-left embedding
        '\u202c',  # Pop directional formatting
        '\u202d',  # Left-to-right override
        '\u202e',  # Right-to-left override
        '\u2066',  # Left-to-right isolate
        '\u2067',  # Right-to-left isolate
        '\u2068',  # First strong isolate
        '\u2069',  # Pop directional isolate
    ]

    def __init__(self):
        """Initialize the detector."""
        self._compiled_patterns = [
            re.compile(p, re.IGNORECASE)
            for p in self.INJECTION_PATTERNS
        ]

    async def scan(self, content: str, source: str = "unknown") -> ThreatDetectionResult:
        """
        Scan content for prompt injection and hidden threats.

        Args:
            content: Content to scan for threats
            source: Source of the content (for logging)

        Returns:
            ThreatDetectionResult with aggregated threat findings
        """
        threats = []

        logger.debug(
            "Threat scan requested",
            extra={
                "source": source,
                "content_length": len(content) if content else 0,
            }
        )

        if not content:
            return ThreatDetectionResult(
                has_violations=False,
                threats=[],
                scanned_content_length=0
            )

        # Call all sub-detectors and aggregate results
        hidden_text_threats = await self.detect_hidden_text(content)
        threats.extend(hidden_text_threats)

        encoded_threats = await self.detect_encoded_content(content)
        threats.extend(encoded_threats)

        injection_threats = await self.detect_prompt_injection(content)
        threats.extend(injection_threats)

        unicode_threats = await self.detect_unicode_attacks(content)
        threats.extend(unicode_threats)

        if threats:
            logger.warning(
                "Threats detected in content",
                extra={
                    "source": source,
                    "threat_count": len(threats),
                    "threat_types": [t.threat_type for t in threats]
                }
            )

        return ThreatDetectionResult(
            has_violations=len(threats) > 0,
            threats=threats,
            scanned_content_length=len(content)
        )

    async def detect_hidden_text(self, content: str) -> list[ThreatMatch]:
        """
        Detect hidden text patterns in content.

        Detects:
        - White text on white background (CSS)
        - Zero-size text
        - Off-screen positioned text
        - Display:none content
        - Visibility:hidden content
        """
        threats = []

        # CSS-based hiding patterns
        hidden_css_patterns = [
            (r'color\s*:\s*white\s*;.*?background(?:-color)?\s*:\s*white', 'White text on white background'),
            (r'color\s*:\s*#fff(?:fff)?\s*;', 'White colored text (potential hidden text)'),
            (r'color\s*:\s*rgba?\(\s*255\s*,\s*255\s*,\s*255', 'White rgba text color (potential hidden text)'),
            (r'font-size\s*:\s*0(?:px|pt|em)?', 'Zero-size font (hidden text)'),
            (r'display\s*:\s*none', 'Display none (hidden content)'),
            (r'visibility\s*:\s*hidden', 'Visibility hidden (hidden content)'),
            (r'opacity\s*:\s*0(?:\.0+)?(?:\s*;|\s*})', 'Zero opacity (hidden content)'),
            (r'position\s*:\s*(?:absolute|fixed).*?(?:left|top)\s*:\s*-\d+', 'Off-screen positioned text'),
            (r'text-indent\s*:\s*-\d{3,}', 'Large negative text indent (hidden text)'),
            (r'overflow\s*:\s*hidden.*?height\s*:\s*0', 'Zero-height overflow hidden (hidden content)'),
        ]

        for pattern, description in hidden_css_patterns:
            compiled = re.compile(pattern, re.IGNORECASE | re.DOTALL)
            matches = compiled.findall(content)
            for match in matches:
                preview = match if isinstance(match, str) else str(match)
                threats.append(ThreatMatch(
                    threat_type="hidden_text",
                    severity="high",
                    description=description,
                    content_preview=preview[:100],
                    location="content"
                ))

        # HTML-based hiding patterns
        html_hidden_patterns = [
            (r'<[^>]+\s+hidden(?:\s|>|/)', 'HTML hidden attribute'),
            (r'<[^>]+\s+aria-hidden\s*=\s*["\']true["\']', 'ARIA hidden element'),
        ]

        for pattern, description in html_hidden_patterns:
            compiled = re.compile(pattern, re.IGNORECASE)
            matches = compiled.findall(content)
            for match in matches:
                threats.append(ThreatMatch(
                    threat_type="hidden_text",
                    severity="medium",
                    description=description,
                    content_preview=match[:100],
                    location="content"
                ))

        return threats

    async def detect_encoded_content(self, content: str) -> list[ThreatMatch]:
        """
        Detect and decode potentially malicious encoded content.

        Detects:
        - Base64 encoded prompts
        - URL encoded content
        - Unicode escape sequences
        - HTML entities
        """
        threats = []

        # Base64 detection and decoding
        b64_pattern = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
        b64_matches = b64_pattern.findall(content)
        for match in b64_matches:
            try:
                decoded = base64.b64decode(match).decode('utf-8')
                # Check decoded content for injection patterns
                for pattern in self._compiled_patterns:
                    if pattern.search(decoded):
                        threats.append(ThreatMatch(
                            threat_type="encoded_content",
                            severity="critical",
                            description="Base64 encoded prompt injection detected",
                            content_preview=decoded[:100],
                            location="base64_encoded_block"
                        ))
                        break
                # Also flag if decoded content looks like instructions
                if any(kw in decoded.lower() for kw in ['ignore', 'system', 'instruction', 'override', 'jailbreak']):
                    threats.append(ThreatMatch(
                        threat_type="encoded_content",
                        severity="high",
                        description="Suspicious base64 encoded content with injection keywords",
                        content_preview=decoded[:100],
                        location="base64_encoded_block"
                    ))
            except Exception:
                pass

        # URL encoded content detection
        url_encoded_pattern = re.compile(r'(?:%[0-9A-Fa-f]{2}){5,}')
        url_matches = url_encoded_pattern.findall(content)
        for match in url_matches:
            try:
                decoded = urllib.parse.unquote(match)
                for pattern in self._compiled_patterns:
                    if pattern.search(decoded):
                        threats.append(ThreatMatch(
                            threat_type="encoded_content",
                            severity="critical",
                            description="URL encoded prompt injection detected",
                            content_preview=decoded[:100],
                            location="url_encoded_block"
                        ))
                        break
            except Exception:
                pass

        # Unicode escape sequences
        unicode_escape_pattern = re.compile(r'(?:\\u[0-9A-Fa-f]{4}){3,}')
        unicode_matches = unicode_escape_pattern.findall(content)
        for match in unicode_matches:
            try:
                decoded = match.encode('utf-8').decode('unicode_escape')
                for pattern in self._compiled_patterns:
                    if pattern.search(decoded):
                        threats.append(ThreatMatch(
                            threat_type="encoded_content",
                            severity="high",
                            description="Unicode escape encoded prompt injection detected",
                            content_preview=decoded[:100],
                            location="unicode_escape_block"
                        ))
                        break
            except Exception:
                pass

        # HTML entity encoded content
        html_entity_pattern = re.compile(r'(?:&(?:#\d+|#x[0-9A-Fa-f]+|[a-zA-Z]+);){5,}')
        html_matches = html_entity_pattern.findall(content)
        for match in html_matches:
            try:
                import html
                decoded = html.unescape(match)
                for pattern in self._compiled_patterns:
                    if pattern.search(decoded):
                        threats.append(ThreatMatch(
                            threat_type="encoded_content",
                            severity="high",
                            description="HTML entity encoded prompt injection detected",
                            content_preview=decoded[:100],
                            location="html_entity_block"
                        ))
                        break
            except Exception:
                pass

        return threats

    async def detect_prompt_injection(self, content: str) -> list[ThreatMatch]:
        """
        Detect known prompt injection patterns.

        Detects patterns like:
        - "ignore previous instructions"
        - "new system prompt"
        - Role-playing attacks
        - Delimiter injection
        """
        threats = []

        for pattern in self._compiled_patterns:
            matches = pattern.findall(content)
            for match in matches:
                preview = match if isinstance(match, str) else ' '.join(match)
                threats.append(ThreatMatch(
                    threat_type="prompt_injection",
                    severity="high",
                    description=f"Detected prompt injection pattern: '{pattern.pattern}'",
                    content_preview=preview[:100],
                    location="content"
                ))

        return threats

    async def detect_unicode_attacks(self, content: str) -> list[ThreatMatch]:
        """
        Detect unicode-based attacks including homoglyphs.

        Detects:
        - Homoglyph substitution (Cyrillic a for Latin a)
        - Bidirectional text attacks
        - Zero-width characters
        - Combining characters
        """
        threats = []

        # Check for zero-width characters
        found_zero_width = [ch for ch in self.ZERO_WIDTH_CHARS if ch in content]
        if found_zero_width:
            threats.append(ThreatMatch(
                threat_type="unicode_attack",
                severity="high",
                description=f"Zero-width characters detected (potential hidden content): {[repr(c) for c in found_zero_width]}",
                content_preview=content[:100],
                location="content"
            ))

        # Check for bidi override characters
        found_bidi = [ch for ch in self.BIDI_OVERRIDE_CHARS if ch in content]
        if found_bidi:
            threats.append(ThreatMatch(
                threat_type="unicode_attack",
                severity="high",
                description=f"Bidirectional text override characters detected: {[repr(c) for c in found_bidi]}",
                content_preview=content[:100],
                location="content"
            ))

        # Check for homoglyph substitution
        homoglyph_chars_found = [ch for ch in self.HOMOGLYPH_MAP.keys() if ch in content]
        if homoglyph_chars_found:
            # Normalize and check if the normalized version contains injection patterns
            normalized = content
            for homoglyph, replacement in self.HOMOGLYPH_MAP.items():
                normalized = normalized.replace(homoglyph, replacement)

            for pattern in self._compiled_patterns:
                if pattern.search(normalized) and not pattern.search(content):
                    threats.append(ThreatMatch(
                        threat_type="unicode_attack",
                        severity="critical",
                        description=f"Homoglyph substitution used to obfuscate prompt injection (chars: {homoglyph_chars_found})",
                        content_preview=content[:100],
                        location="content"
                    ))
                    break

            if homoglyph_chars_found and not any(t.threat_type == "unicode_attack" and "Homoglyph" in t.description for t in threats):
                threats.append(ThreatMatch(
                    threat_type="unicode_attack",
                    severity="medium",
                    description=f"Homoglyph characters detected (potential obfuscation): {homoglyph_chars_found}",
                    content_preview=content[:100],
                    location="content"
                ))

        # Check for unusual combining characters (potential obfuscation)
        combining_pattern = re.compile(r'[\u0300-\u036f\u1dc0-\u1dff\u20d0-\u20ff]{3,}')
        combining_matches = combining_pattern.findall(content)
        if combining_matches:
            threats.append(ThreatMatch(
                threat_type="unicode_attack",
                severity="medium",
                description="Excessive combining characters detected (potential obfuscation)",
                content_preview=content[:100],
                location="content"
            ))

        return threats

    async def scan_metadata(self, metadata: dict) -> ThreatDetectionResult:
        """
        Scan file metadata for hidden threats.

        Scans:
        - EXIF comments and descriptions
        - PDF metadata fields
        - Document properties
        - Custom metadata tags
        """
        threats = []
        metadata_str = str(metadata)

        # Flatten metadata values for scanning
        def extract_values(d, prefix=""):
            values = []
            if isinstance(d, dict):
                for k, v in d.items():
                    values.extend(extract_values(v, prefix=f"{prefix}.{k}" if prefix else str(k)))
            elif isinstance(d, (list, tuple)):
                for i, v in enumerate(d):
                    values.extend(extract_values(v, prefix=f"{prefix}[{i}]"))
            else:
                values.append((prefix, str(d)))
            return values

        metadata_values = extract_values(metadata)

        for field_path, value in metadata_values:
            # Check each metadata value for injection patterns
            for pattern in self._compiled_patterns:
                if pattern.search(value):
                    threats.append(ThreatMatch(
                        threat_type="metadata_injection",
                        severity="high",
                        description=f"Prompt injection pattern detected in metadata field '{field_path}'",
                        content_preview=value[:100],
                        location=f"metadata.{field_path}"
                    ))
                    break

            # Check for encoded content in metadata values
            encoded_threats = await self.detect_encoded_content(value)
            for threat in encoded_threats:
                threat.location = f"metadata.{field_path}"
                threat.threat_type = "metadata_injection"
                threats.append(threat)

            # Check for unicode attacks in metadata values
            unicode_threats = await self.detect_unicode_attacks(value)
            for threat in unicode_threats:
                threat.location = f"metadata.{field_path}"
                threat.threat_type = "metadata_injection"
                threats.append(threat)

        return ThreatDetectionResult(
            has_violations=len(threats) > 0,
            threats=threats,
            scanned_content_length=len(metadata_str)
        )

    def _decode_base64(self, content: str) -> Optional[str]:
        """Attempt to decode base64 content."""
        try:
            # Look for base64-like strings
            b64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
            matches = re.findall(b64_pattern, content)

            for match in matches:
                try:
                    decoded = base64.b64decode(match).decode('utf-8')
                    return decoded
                except:
                    continue
            return None
        except:
            return None


# ============================================================================
# REMEDIATED VERSION (commented out - Unifai would enable this)
# ============================================================================

# class PromptInjectionDetector:
#     """
#     SECURE VERSION - After Unifai remediation
#
#     This version:
#     - Actually scans for prompt injection patterns
#     - Detects hidden text in various formats
#     - Decodes and scans base64 content
#     - Identifies unicode attacks
#     """
#
#     async def scan(self, content: str, source: str = "unknown") -> ThreatDetectionResult:
#         """Perform comprehensive threat scanning."""
#         threats = []
#
#         # Check for prompt injection patterns
#         for pattern in self._compiled_patterns:
#             matches = pattern.findall(content)
#             for match in matches:
#                 threats.append(ThreatMatch(
#                     threat_type="prompt_injection",
#                     severity="high",
#                     description=f"Detected prompt injection pattern",
#                     content_preview=match,
#                     location=source
#                 ))
#
#         # Check for hidden/encoded content
#         encoded_threats = await self.detect_encoded_content(content)
#         threats.extend(encoded_threats)
#
#         # Check for unicode attacks
#         unicode_threats = await self.detect_unicode_attacks(content)
#         threats.extend(unicode_threats)
#
#         return ThreatDetectionResult(
#             has_violations=len(threats) > 0,
#             threats=threats,
#             scanned_content_length=len(content)
#         )