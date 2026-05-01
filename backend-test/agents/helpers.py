"""Shared helper functions for the PolicyProbe agents."""

import base64
import re
from typing import Any
from uuid import uuid4


_MALICIOUS_PATTERNS = [
    # Hidden/invisible text via Unicode control characters
    re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u206a-\u206f\ufeff]"),
    # Shell command patterns
    re.compile(r"(?i)(;\s*rm\s+-|&&\s*curl\s+|`[^`]*`|\$\([^)]*\)|\|\s*bash|\|\s*sh\b)"),
    # Binary executable signatures (ELF, PE, Mach-O)
    re.compile(r"(?:\x7fELF|MZ\x90|^\xca\xfe\xba\xbe)", re.DOTALL),
    # Prompt injection patterns
    re.compile(
        r"(?i)(ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)|"
        r"you\s+are\s+now\s+|new\s+instructions?:|system\s*:\s*you|"
        r"disregard\s+(all\s+)?(previous|prior)|forget\s+(all\s+)?(previous|prior)|"
        r"act\s+as\s+if\s+you|pretend\s+you\s+are|jailbreak|"
        r"<\s*system\s*>|<\s*/?inst\s*>|\[INST\]|\[/INST\])"
    ),
    # Leetspeak patterns (common substitutions used to evade filters)
    re.compile(r"(?i)\b(?:[i1][g9][n][o0][r3][e3]|[s5][y][s5][t][e3][m3]|[e3][x][e3][c])\b"),
    # Suspicious base64-encoded command patterns within text
    re.compile(r"(?i)(eval\s*\(|exec\s*\(|__import__\s*\(|subprocess|os\.system|shell=True)"),
]


def _is_malicious_content(text: str) -> bool:
    """Return True if the text contains malicious or suspicious content."""
    if not text:
        return False
    for pattern in _MALICIOUS_PATTERNS:
        if pattern.search(text):
            return True
    return False


def _sanitize_content(text: str, placeholder: str = "[content removed: malicious pattern detected]") -> str:
    """Return sanitized content, replacing malicious content with a placeholder."""
    if _is_malicious_content(text):
        return placeholder
    return text


def build_file_summary(
    file_contents: list[dict[str, Any]],
    include_raw_text: bool = False,
) -> str:
    if not file_contents:
        return "No files were attached."

    sections = []
    for file_data in file_contents:
        extracted_content = file_data.get("extracted_content", "")
        extracted_content = _sanitize_content(extracted_content)
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
            sanitized = _sanitize_content(decoded.strip())
            decoded_segments.append(sanitized)
    return decoded_segments


def extract_base64_candidates(content: str) -> list[str]:
    return re.findall(r"[A-Za-z0-9+/=]{24,}", content or "")