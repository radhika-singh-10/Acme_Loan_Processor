"""Shared helper functions for the PolicyProbe agents."""

import base64
import re
import unicodedata
from typing import Any
from uuid import uuid4


# ---------------------------------------------------------------------------
# PII redaction helpers
# ---------------------------------------------------------------------------

_PII_PATTERNS: list[tuple[str, str]] = [
    # SSN (US)
    (r"\b\d{3}-\d{2}-\d{4}\b", "[REDACTED-SSN]"),
    # Credit card numbers (basic Luhn-ish patterns)
    (r"\b(?:\d[ -]?){13,16}\b", "[REDACTED-CC]"),
    # Email addresses
    (r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", "[REDACTED-EMAIL]"),
    # Phone numbers (US and international variants)
    (r"\b(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}\b", "[REDACTED-PHONE]"),
    # Medical record numbers (MRN)
    (r"\bMRN[:\s#]*\d{5,10}\b", "[REDACTED-MRN]"),
    # Home addresses (simple heuristic: number + street name + street type)
    (
        r"\b\d{1,5}\s+[A-Za-z0-9\s]{1,40}"
        r"(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\b",
        "[REDACTED-ADDRESS]",
    ),
    # Singapore NRIC/FIN  (S/T/F/G + 7 digits + letter)
    (r"\b[STFG]\d{7}[A-Za-z]\b", "[REDACTED-NRIC]"),
    # Singapore phone numbers (+65 XXXX XXXX)
    (r"\b(?:\+65[\s-]?)?\d{4}[\s-]?\d{4}\b", "[REDACTED-SG-PHONE]"),
    # Singapore postal codes (6 digits, often preceded by "Singapore")
    (r"\bSingapore\s+\d{6}\b", "[REDACTED-SG-POSTAL]"),
    (r"\b\d{6}\b", "[REDACTED-POSTAL]"),
]

# Singapore-specific PII patterns for detection
_SG_PII_PATTERNS: list[re.Pattern] = [
    re.compile(r"\b[STFG]\d{7}[A-Za-z]\b"),          # NRIC/FIN
    re.compile(r"\b(?:\+65[\s-]?)?\d{4}[\s-]?\d{4}\b"),  # SG phone
    re.compile(r"\bSingapore\s+\d{6}\b"),              # SG postal
]


def redact_pii(text: str) -> str:
    """Redact common PII categories from text using regex patterns."""
    if not text:
        return text
    for pattern, replacement in _PII_PATTERNS:
        text = re.sub(pattern, replacement, text, flags=re.IGNORECASE)
    return text


def detect_singapore_pii(text: str) -> bool:
    """Return True if Singapore-specific PII is detected in text."""
    for pattern in _SG_PII_PATTERNS:
        if pattern.search(text):
            return True
    return False


# ---------------------------------------------------------------------------
# Prompt-injection / malicious-content sanitization helpers
# ---------------------------------------------------------------------------

# Zero-width and invisible Unicode characters
_ZERO_WIDTH_CHARS = re.compile(
    r"[\u200b\u200c\u200d\u200e\u200f\u202a-\u202e\u2060-\u2064\ufeff\u00ad]"
)

# Control characters (except common whitespace: tab, newline, carriage return)
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")

# Suspicious prompt-injection phrases
_INJECTION_PHRASES = re.compile(
    r"(?i)("
    r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context)|"
    r"disregard\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context)|"
    r"forget\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context)|"
    r"you\s+are\s+now\s+(?:a\s+)?(?:an?\s+)?(?:different|new|another|evil|unrestricted)|"
    r"act\s+as\s+(?:a\s+)?(?:an?\s+)?(?:different|new|another|evil|unrestricted|DAN)|"
    r"pretend\s+(?:you\s+are|to\s+be)\s+(?:a\s+)?(?:an?\s+)?(?:different|new|another|evil|unrestricted)|"
    r"new\s+instructions?:|"
    r"system\s*prompt:|"
    r"<\s*/?(?:system|instruction|prompt|context|override)\s*>|"
    r"\[INST\]|\[/INST\]|<\|im_start\|>|<\|im_end\|>|"
    r"jailbreak|"
    r"bypass\s+(?:the\s+)?(?:filter|restriction|policy|safety|guard)|"
    r"override\s+(?:the\s+)?(?:filter|restriction|policy|safety|guard)"
    r")"
)

# Leetspeak pattern (common substitutions: 4=a, 3=e, 1=i/l, 0=o, 5=s, 7=t)
_LEETSPEAK = re.compile(
    r"(?i)\b(?:[a-z]*[4310573@$!][a-z0-9]*){3,}\b"
)

# Binary/shell command indicators
_SHELL_INDICATORS = re.compile(
    r"(?i)("
    r"(?:^|\s)(?:bash|sh|zsh|cmd|powershell|python|perl|ruby|php|node)\s+[-/]|"
    r"(?:^|\s)(?:curl|wget|nc|ncat|netcat|nmap|chmod|chown|sudo|su\s|rm\s+-rf|"
    r"eval\s*\(|exec\s*\(|os\.system|subprocess|__import__)|"
    r"\$\([^)]{1,80}\)|"
    r"`[^`]{1,80}`"
    r")"
)

# Tiny-font / white-on-white HTML markers (for HTML content that slipped through)
_HIDDEN_TEXT_HTML = re.compile(
    r"(?i)(?:color\s*:\s*(?:white|#fff(?:fff)?|rgba?\([^)]*,\s*0\))|"
    r"font-size\s*:\s*[01](?:\.\d+)?(?:px|pt|em|rem)|"
    r"visibility\s*:\s*hidden|"
    r"display\s*:\s*none|"
    r"opacity\s*:\s*0(?:\.\d+)?)"
)


def _strip_zero_width(text: str) -> str:
    return _ZERO_WIDTH_CHARS.sub("", text)


def _strip_control_chars(text: str) -> str:
    return _CONTROL_CHARS.sub("", text)


def _flag_injection_phrases(text: str) -> str:
    return _INJECTION_PHRASES.sub("[REDACTED-INJECTION]", text)


def _flag_leetspeak(text: str) -> str:
    return _LEETSPEAK.sub("[REDACTED-LEETSPEAK]", text)


def _flag_shell_commands(text: str) -> str:
    return _SHELL_INDICATORS.sub("[REDACTED-SHELL]", text)


def _flag_hidden_html(text: str) -> str:
    return _HIDDEN_TEXT_HTML.sub("[REDACTED-HIDDEN]", text)


def _flag_base64_payloads(text: str) -> str:
    """Replace base64 segments that decode to suspicious content."""
    candidates = extract_base64_candidates(text)
    for candidate in candidates:
        if len(candidate) % 4 != 0:
            continue
        try:
            decoded = base64.b64decode(candidate, validate=True).decode("utf-8")
        except Exception:
            continue
        decoded_stripped = decoded.strip()
        if not decoded_stripped:
            continue
        # If the decoded content itself looks suspicious, redact the original segment
        if (
            _INJECTION_PHRASES.search(decoded_stripped)
            or _SHELL_INDICATORS.search(decoded_stripped)
            or len(decoded_stripped) > 200
        ):
            text = text.replace(candidate, "[REDACTED-BASE64]")
    return text


def sanitize_extracted_content(text: str) -> str:
    """
    Strip prompt-injection patterns, control characters, hidden text markers,
    leetspeak, shell command indicators, and base64-encoded payloads from
    extracted file text before it is inserted into LLM prompts.
    """
    if not text:
        return text

    # Normalize unicode to NFC to catch homoglyph tricks
    text = unicodedata.normalize("NFC", text)

    # Remove zero-width / invisible characters
    text = _strip_zero_width(text)

    # Remove control characters
    text = _strip_control_chars(text)

    # Flag hidden HTML styling
    text = _flag_hidden_html(text)

    # Flag base64 payloads before other substitutions alter the text
    text = _flag_base64_payloads(text)

    # Flag prompt-injection phrases
    text = _flag_injection_phrases(text)

    # Flag leetspeak
    text = _flag_leetspeak(text)

    # Flag shell/binary command indicators
    text = _flag_shell_commands(text)

    return text


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_file_summary(
    file_contents: list[dict[str, Any]],
    include_raw_text: bool = False,
) -> str:
    if not file_contents:
        return "No files were attached."

    sections = []
    for file_data in file_contents:
        extracted_content = file_data.get("extracted_content", "")

        # --- Security pipeline ---
        # 1. Sanitize for prompt-injection / malicious content
        extracted_content = sanitize_extracted_content(extracted_content)

        # 2. Detect and handle Singapore PII
        if detect_singapore_pii(extracted_content):
            # Redact rather than raise so processing can continue safely
            extracted_content = redact_pii(extracted_content)
        else:
            # 3. Redact general PII
            extracted_content = redact_pii(extracted_content)

        # 4. Truncate if needed
        if not include_raw_text and len(extracted_content) > 600:
            extracted_content = extracted_content[:600] + "..."

        sections.append(
            f"Filename: {file_data.get('filename', 'unknown')}\n"
            f"Content Type: {file_data.get('content_type', 'unknown')}\n"
            f"Extracted Content:\n{extracted_content}"
        )

    return "\n\n".join(sections)


def extract_reference_number(message: str, prefix: str) -> str:
    match = re.search(r"\b([A-Z]{2,}-\d{2,}|\d{4,})\b", message or "")
    if match:
        return str(match.group(1))
    return f"{prefix}-{str(uuid4())[:8].upper()}"


def decode_base64_segments(content: str) -> list[str]:
    decoded_segments: list[str] = []
    for candidate in extract_base64_candidates(content):
        if len(candidate) % 4 != 0:
            continue
        try:
            decoded = base64.b64decode(candidate, validate=True).decode("utf-8")
        except Exception:
            continue
        if decoded.strip():
            decoded_segments.append(decoded.strip())
    return decoded_segments


def extract_base64_candidates(content: str) -> list[str]:
    return re.findall(r"[A-Za-z0-9+/=]{24,}", content or "")