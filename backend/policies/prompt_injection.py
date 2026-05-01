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

    # CSS/HTML hidden text patterns
    HIDDEN_TEXT_PATTERNS = [
        r'color\s*:\s*white',
        r'color\s*:\s*#fff(?:fff)?(?:\s|;|")',
        r'font-size\s*:\s*0',
        r'display\s*:\s*none',
        r'visibility\s*:\s*hidden',
        r'opacity\s*:\s*0',
        r'position\s*:\s*absolute.*left\s*:\s*-\d+',
        r'position\s*:\s*absolute.*top\s*:\s*-\d+',
        r'overflow\s*:\s*hidden.*height\s*:\s*0',
        r'height\s*:\s*0.*overflow\s*:\s*hidden',
        r'width\s*:\s*0.*overflow\s*:\s*hidden',
        r'text-indent\s*:\s*-\d+',
        r'clip\s*:\s*rect\s*\(\s*0\s*,\s*0\s*,\s*0\s*,\s*0\s*\)',
    ]

    # Zero-width and bidi characters
    ZERO_WIDTH_CHARS = [
        '\u200b',  # Zero-width space
        '\u200c',  # Zero-width non-joiner
        '\u200d',  # Zero-width joiner
        '\ufeff',  # Zero-width no-break space (BOM)
        '\u2060',  # Word joiner
        '\u00ad',  # Soft hyphen
    ]

    BIDI_CHARS = [
        '\u202a',  # Left-to-right embedding
        '\u202b',  # Right-to-left embedding
        '\u202c',  # Pop directional formatting
        '\u202d',  # Left-to-right override
        '\u202e',  # Right-to-left override
        '\u2066',  # Left-to-right isolate
        '\u2067',  # Right-to-left isolate
        '\u2068',  # First strong isolate
        '\u2069',  # Pop directional isolate
        '\u200f',  # Right-to-left mark
        '\u200e',  # Left-to-right mark
    ]

    def __init__(self):
        """Initialize the detector."""
        self._compiled_patterns = [
            re.compile(p, re.IGNORECASE)
            for p in self.INJECTION_PATTERNS
        ]
        self._compiled_hidden_patterns = [
            re.compile(p, re.IGNORECASE | re.DOTALL)
            for p in self.HIDDEN_TEXT_PATTERNS
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
        if not content:
            return ThreatDetectionResult(
                has_violations=False,
                threats=[],
                scanned_content_length=0
            )

        logger.debug(
            "Threat scan requested",
            extra={
                "source": source,
                "content_length": len(content),
            }
        )

        threats = []

        # Run all detection sub-methods and aggregate results
        prompt_injection_threats = await self.detect_prompt_injection(content)
        threats.extend(prompt_injection_threats)

        hidden_text_threats = await self.detect_hidden_text(content)
        threats.extend(hidden_text_threats)

        encoded_content_threats = await self.detect_encoded_content(content)
        threats.extend(encoded_content_threats)

        unicode_attack_threats = await self.detect_unicode_attacks(content)
        threats.extend(unicode_attack_threats)

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

        for pattern in self._compiled_hidden_patterns:
            matches = pattern.findall(content)
            for match in matches:
                preview = match if isinstance(match, str) else str(match)
                threats.append(ThreatMatch(
                    threat_type="hidden_text",
                    severity="high",
                    description=f"Detected CSS/HTML hidden text technique: {preview[:80]}",
                    content_preview=preview,
                    location="content"
                ))

        # Check for HTML comment-based hiding
        comment_pattern = re.compile(r'<!--.*?-->', re.DOTALL)
        comments = comment_pattern.findall(content)
        for comment in comments:
            # Check if comment contains injection patterns
            for inj_pattern in self._compiled_patterns:
                if inj_pattern.search(comment):
                    threats.append(ThreatMatch(
                        threat_type="hidden_text",
                        severity="high",
                        description="Detected prompt injection pattern inside HTML comment",
                        content_preview=comment[:100],
                        location="html_comment"
                    ))
                    break

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
                decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                if decoded and len(decoded) > 5:
                    # Re-scan decoded content for injection patterns
                    for inj_pattern in self._compiled_patterns:
                        if inj_pattern.search(decoded):
                            threats.append(ThreatMatch(
                                threat_type="encoded_content",
                                severity="critical",
                                description=f"Detected prompt injection in base64-decoded content",
                                content_preview=decoded[:100],
                                location="base64_encoded"
                            ))
                            break
                    else:
                        # Also check for hidden text patterns in decoded content
                        for hidden_pattern in self._compiled_hidden_patterns:
                            if hidden_pattern.search(decoded):
                                threats.append(ThreatMatch(
                                    threat_type="encoded_content",
                                    severity="high",
                                    description="Detected hidden text technique in base64-decoded content",
                                    content_preview=decoded[:100],
                                    location="base64_encoded"
                                ))
                                break
            except Exception:
                continue

        # URL encoding detection
        url_encoded_pattern = re.compile(r'(?:%[0-9A-Fa-f]{2}){5,}')
        url_matches = url_encoded_pattern.findall(content)
        for match in url_matches:
            try:
                decoded = urllib.parse.unquote(match)
                for inj_pattern in self._compiled_patterns:
                    if inj_pattern.search(decoded):
                        threats.append(ThreatMatch(
                            threat_type="encoded_content",
                            severity="critical",
                            description="Detected prompt injection in URL-encoded content",
                            content_preview=decoded[:100],
                            location="url_encoded"
                        ))
                        break
            except Exception:
                continue

        # Unicode escape sequence detection
        unicode_escape_pattern = re.compile(r'(?:\\u[0-9A-Fa-f]{4}){3,}')
        unicode_matches = unicode_escape_pattern.findall(content)
        for match in unicode_matches:
            try:
                decoded = match.encode('utf-8').decode('unicode_escape')
                for inj_pattern in self._compiled_patterns:
                    if inj_pattern.search(decoded):
                        threats.append(ThreatMatch(
                            threat_type="encoded_content",
                            severity="high",
                            description="Detected prompt injection in unicode-escaped content",
                            content_preview=decoded[:100],
                            location="unicode_escaped"
                        ))
                        break
            except Exception:
                continue

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
            matches = pattern.finditer(content)
            for match in matches:
                matched_text = match.group(0)
                # Get some surrounding context
                start = max(0, match.start() - 20)
                end = min(len(content), match.end() + 20)
                context = content[start:end]
                threats.append(ThreatMatch(
                    threat_type="prompt_injection",
                    severity="high",
                    description=f"Detected prompt injection pattern: '{matched_text}'",
                    content_preview=context,
                    location=f"offset_{match.start()}"
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
        found_zero_width = []
        for char in self.ZERO_WIDTH_CHARS:
            if char in content:
                found_zero_width.append(f'U+{ord(char):04X}')

        if found_zero_width:
            threats.append(ThreatMatch(
                threat_type="unicode_attack",
                severity="high",
                description=f"Detected zero-width characters that may hide content: {', '.join(found_zero_width)}",
                content_preview=content[:100],
                location="content"
            ))

        # Check for bidi override characters
        found_bidi = []
        for char in self.BIDI_CHARS:
            if char in content:
                found_bidi.append(f'U+{ord(char):04X}')

        if found_bidi:
            threats.append(ThreatMatch(
                threat_type="unicode_attack",
                severity="high",
                description=f"Detected bidirectional text override characters: {', '.join(found_bidi)}",
                content_preview=content[:100],
                location="content"
            ))

        # Check for homoglyph substitution
        homoglyph_chars_found = []
        for char in content:
            if char in self.HOMOGLYPH_MAP:
                homoglyph_chars_found.append(f"'{char}' (looks like '{self.HOMOGLYPH_MAP[char]}')")

        if homoglyph_chars_found:
            # Normalize content using homoglyph map and re-check for injection patterns
            normalized = content
            for homoglyph, replacement in self.HOMOGLYPH_MAP.items():
                normalized = normalized.replace(homoglyph, replacement)

            for inj_pattern in self._compiled_patterns:
                if inj_pattern.search(normalized):
                    threats.append(ThreatMatch(
                        threat_type="unicode_attack",
                        severity="critical",
                        description=f"Detected homoglyph-obfuscated prompt injection using characters: {', '.join(set(homoglyph_chars_found[:5]))}",
                        content_preview=normalized[:100],
                        location="content"
                    ))
                    break
            else:
                if len(homoglyph_chars_found) > 3:
                    threats.append(ThreatMatch(
                        threat_type="unicode_attack",
                        severity="medium",
                        description=f"Detected multiple homoglyph characters that may be used for obfuscation",
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

        # Scan stringified metadata for injection patterns
        for pattern in self._compiled_patterns:
            matches = pattern.finditer(metadata_str)
            for match in matches:
                matched_text = match.group(0)
                start = max(0, match.start() - 20)
                end = min(len(metadata_str), match.end() + 20)
                context = metadata_str[start:end]
                threats.append(ThreatMatch(
                    threat_type="metadata_injection",
                    severity="high",
                    description=f"Detected prompt injection pattern in metadata: '{matched_text}'",
                    content_preview=context,
                    location="metadata"
                ))

        # Also scan individual metadata values if they are strings
        if isinstance(metadata, dict):
            for key, value in metadata.items():
                if isinstance(value, str):
                    # Check for base64 encoded content in metadata values
                    decoded = self._decode_base64(value)
                    if decoded:
                        for inj_pattern in self._compiled_patterns:
                            if inj_pattern.search(decoded):
                                threats.append(ThreatMatch(
                                    threat_type="metadata_injection",
                                    severity="critical",
                                    description=f"Detected prompt injection in base64-encoded metadata field '{key}'",
                                    content_preview=decoded[:100],
                                    location=f"metadata.{key}"
                                ))
                                break

        if threats:
            logger.warning(
                "Threats detected in metadata",
                extra={
                    "threat_count": len(threats),
                    "threat_types": [t.threat_type for t in threats]
                }
            )

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