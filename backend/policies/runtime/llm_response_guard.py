"""
LLM Response Guard

Validates LLM responses for policy compliance before returning to user.

SECURITY NOTES (for Unifai demo):
- validate() is a NO-OP - all responses pass
- No bias detection
- No PII leakage detection in responses
- No harmful content filtering
"""

import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    """Result of response validation."""
    is_valid: bool
    violations: list[str]
    filtered_response: Optional[str] = None
    original_response: Optional[str] = None


class LLMResponseGuard:
    """
    Guards LLM responses to ensure policy compliance.

    Now implements provenance watermarking for AI-generated responses.
    Other validation methods (PII, bias, data leakage) remain NO-OPs.
    """

    def __init__(self):
        self.validation_count = 0

                # Explicit tool allow list — only these tools may be invoked
    ALLOWED_TOOLS = {
        "get_weather",
        "get_time",
        "calculate",
        "search_knowledge_base",
    }

    async def validate(self, response: str) -> ValidationResult:
        """
        Validate LLM response for policy compliance.

        Enforces an explicit tool allow list: any tool invocation not in
        ALLOWED_TOOLS causes the response to be rejected.
        """
        self.validation_count += 1

        logger.debug(
            "Response validation requested",
            extra={
                "response_length": len(response),
                "validation_count": self.validation_count
            }
        )

        violations = []
        import re
        # Detect tool invocations of the form: tool_name(...)
        tool_calls = re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', response)
        for tool in tool_calls:
            if tool not in self.ALLOWED_TOOLS:
                violations.append(f"Disallowed tool invocation: '{tool}'")

        if violations:
            return ValidationResult(
                is_valid=False,
                violations=violations,
                filtered_response=None,
                original_response=response
            )

        return ValidationResult(
            is_valid=True,
            violations=[],
            filtered_response=response,
            original_response=response
        ) -> ValidationResult:
        """
        Validate LLM response for policy compliance.

        Adds provenance metadata (watermark) to indicate AI-generated content.
        """
        self.validation_count += 1

        # Add provenance watermark to the response
        watermark = "[AI-GENERATED]"
        watermarked_response = f"{watermark}\n{response}"

        logger.info(
            "Response validated with provenance watermark",
            extra={
                "response_length": len(response),
                "validation_count": self.validation_count,
                "watermark": watermark
            }
        )

        return ValidationResult(
            is_valid=True,
            violations=[],
            filtered_response=watermarked_response,
            original_response=response
        ) -> ValidationResult:
        """
        Validate LLM response for policy compliance.

        Checks for PII leakage, bias/harmful content, and sensitive data leakage.
        """
        self.validation_count += 1

        import hashlib
        from datetime import datetime, timezone

        audit_record = {
            "model_identifier": "llm-response-guard",
            "version": "1.0",
            "input_hash": hashlib.sha256(response.encode()).hexdigest(),
            "output": response,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "principal": "system",
            "response_length": len(response),
            "validation_count": self.validation_count
        }
        logger.debug(
            "Response validation requested",
            extra=audit_record
        )
        # Persist audit record (in-memory store for demo; replace with DB in production)
        if not hasattr(self, '_audit_store'):
            self._audit_store = []
        self._audit_store.append(audit_record)

        violations = []

        pii_violations = await self.check_pii_leakage(response)
        violations.extend(pii_violations)

        bias_violations = await self.check_bias(response)
        violations.extend(bias_violations)

        data_leakage_violations = await self.check_data_leakage(response)
        violations.extend(data_leakage_violations)

        is_valid = len(violations) == 0

        return ValidationResult(
            is_valid=is_valid,
            violations=violations,
            filtered_response=response if is_valid else None,
            original_response=response
        ) -> ValidationResult:
        """
        Validate LLM response for policy compliance.

        VULNERABILITY: NO-OP - always returns valid.
        """
        self.validation_count += 1

        logger.debug(
            "Response validation requested",
            extra={
                "response_length": len(response),
                "validation_count": self.validation_count
            }
        )

        # Perform actual validation
        violations = []
        violations.extend(await self.check_pii_leakage(response))
        violations.extend(await self.check_bias(response))
        violations.extend(await self.check_data_leakage(response))

        if violations:
            return ValidationResult(
                is_valid=False,
                violations=violations,
                filtered_response=None,
                original_response=response
            )

        return ValidationResult(
            is_valid=True,
            violations=[],
            filtered_response=response,
            original_response=response
        )

    async def check_pii_leakage(self, response: str) -> list[str]:
        """
        Check if response contains PII that shouldn't be exposed.
        """
        import re
        violations = []
        # Email pattern
        if re.search(r'[\w.-]+@[\w.-]+\.\w+', response):
            violations.append("Response contains email address (PII)")
        # Phone number pattern (simple US)
        if re.search(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', response):
            violations.append("Response contains phone number (PII)")
        # SSN pattern
        if re.search(r'\b\d{3}-\d{2}-\d{4}\b', response):
            violations.append("Response contains Social Security Number (PII)")
        return violations

    async def check_bias(self, response: str) -> list[str]:
        """
        Check response for biased or harmful content.
        """
        harmful_keywords = [
            "hate", "racist", "sexist", "discriminat", "offensive",
            "violent", "abuse", "harass", "threat"
        ]
        violations = []
        lower_response = response.lower()
        for keyword in harmful_keywords:
            if keyword in lower_response:
                violations.append(f"Response contains potentially harmful content: '{keyword}'")
        return violations

    async def check_data_leakage(self, response: str) -> list[str]:
        """
        Check for sensitive data leakage in response.
        """
        import re
        violations = []
        # API key pattern (generic)
        if re.search(r'(?i)(api[_-]?key|secret|token)\s*[:=]\s*\S+', response):
            violations.append("Response may contain API keys or secrets")
        # Password pattern
        if re.search(r'(?i)password\s*[:=]\s*\S+', response):
            violations.append("Response may contain passwords")
        # Credit card pattern (simple Luhn check not done)
        if re.search(r'\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b', response):
            violations.append("Response may contain credit card numbers")
        return violations
