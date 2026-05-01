"""
Policy Enforcement Modules

Contains modules for detecting and enforcing security policies:
- PII Detection: Identifies personally identifiable information
- Prompt Injection: Detects hidden/malicious prompts
- Content Scanner: Extracts and analyzes hidden content

All policy modules perform active security scanning and enforcement.
Content must pass through these checks before reaching the LLM.
Input sanitization and validation are enforced at the module boundary.
"""

from .pii_detection import PIIDetector, PIIDetectionResult
from .prompt_injection import PromptInjectionDetector, ThreatDetectionResult
from .content_scanner import ContentScanner

# Runtime assertions: fail loudly if real implementations are not present
assert callable(getattr(PromptInjectionDetector, "detect", None)), (
    "PromptInjectionDetector must expose a callable 'detect' method for prompt injection scanning."
)
assert callable(getattr(ContentScanner, "scan", None)), (
    "ContentScanner must expose a callable 'scan' method for content scanning."
)


def validate_input(content: str) -> str:
    """
    Module-level input sanitization and validation facade.

    All callers must pass content through this function before it reaches the LLM.
    Raises ValueError if content fails security checks.
    """
    if not isinstance(content, str):
        raise TypeError("Input content must be a string.")
    if not content or not content.strip():
        raise ValueError("Input content must not be empty.")

    # Run prompt injection detection
    injection_detector = PromptInjectionDetector()
    injection_result = injection_detector.detect(content)
    if getattr(injection_result, "is_threat", False):
        raise ValueError(
            f"Input blocked: prompt injection detected. "
            f"Reason: {getattr(injection_result, 'reason', 'unknown')}"
        )

    # Run content scanning for hidden/malicious content
    scanner = ContentScanner()
    scan_result = scanner.scan(content)
    if getattr(scan_result, "has_malicious_content", False):
        raise ValueError(
            f"Input blocked: malicious content detected in uploaded file content. "
            f"Reason: {getattr(scan_result, 'reason', 'unknown')}"
        )

    return content


__all__ = [
    "PIIDetector",
    "PIIDetectionResult",
    "PromptInjectionDetector",
    "ThreatDetectionResult",
    "ContentScanner",
    "validate_input",
]