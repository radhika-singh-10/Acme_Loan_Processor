"""
Runtime Policy Enforcement

Runtime guardrails that execute during application operation.

SECURITY ENFORCEMENT:
- Real-time LLM output validation
- Input sanitization before processing
- Comprehensive audit logging
- Prompt injection detection and rejection
"""

import re
import logging

logger = logging.getLogger(__name__)

MAX_INPUT_LENGTH = 32768


class InputSanitizer:
    """
    Validates and sanitizes input before processing by the AI model.
    Strips dangerous characters, enforces length limits, and rejects
    null bytes or prompt-injection patterns.
    """

    INJECTION_PATTERNS = [
        re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.IGNORECASE),
        re.compile(r"disregard\s+(all\s+)?previous\s+instructions", re.IGNORECASE),
        re.compile(r"forget\s+(all\s+)?previous\s+instructions", re.IGNORECASE),
        re.compile(r"you\s+are\s+now\s+", re.IGNORECASE),
        re.compile(r"act\s+as\s+(if\s+you\s+are|a\s+)", re.IGNORECASE),
        re.compile(r"system\s*prompt\s*:", re.IGNORECASE),
        re.compile(r"<\s*system\s*>", re.IGNORECASE),
        re.compile(r"\[\s*system\s*\]", re.IGNORECASE),
        re.compile(r"jailbreak", re.IGNORECASE),
        re.compile(r"prompt\s+injection", re.IGNORECASE),
        re.compile(r"override\s+(your\s+)?(instructions|directives|rules)", re.IGNORECASE),
    ]

    DANGEROUS_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

    def sanitize(self, text: str) -> str:
        """
        Sanitize input text. Returns sanitized string.
        Raises ValueError if input is rejected.
        """
        if not isinstance(text, str):
            raise ValueError("Input must be a string")

        if "\x00" in text:
            raise ValueError("Input contains null bytes and has been rejected")

        if len(text) > MAX_INPUT_LENGTH:
            raise ValueError(
                f"Input exceeds maximum allowed length of {MAX_INPUT_LENGTH} characters"
            )

        for pattern in self.INJECTION_PATTERNS:
            if pattern.search(text):
                logger.warning("Prompt injection pattern detected and rejected")
                raise ValueError("Input contains prompt injection pattern and has been rejected")

        sanitized = self.DANGEROUS_CHARS.sub("", text)

        return sanitized

    def validate_and_sanitize(self, text: str) -> str:
        """Alias for sanitize providing validate+sanitize semantics."""
        return self.sanitize(text)


from .llm_response_guard import LLMResponseGuard
from .audit_logger import AuditLogger

__all__ = ["LLMResponseGuard", "InputSanitizer", "AuditLogger"]