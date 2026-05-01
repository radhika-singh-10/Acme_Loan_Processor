"""
LLM Response Guard

Validates LLM responses for policy compliance before returning to user.

SECURITY NOTES (for Unifai demo):
- validate() aggregates violations from all checks
- PII leakage detection in responses
- Harmful content filtering
- Dynamic code execution primitive detection
"""

import logging
import re
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

    Validates:
    - No dynamic code execution primitives in responses
    - No PII in responses
    - No harmful/biased content
    - No sensitive data leakage
    - Compliance with content policies
    """

    # Dynamic code execution primitives
    CODE_EXECUTION_PATTERNS = [
        re.compile(r'\beval\s*\(', re.IGNORECASE),
        re.compile(r'\bexec\s*\(', re.IGNORECASE),
        re.compile(r'\bsubprocess\b.*\bshell\s*=\s*True\b', re.IGNORECASE | re.DOTALL),
        re.compile(r'\bos\.system\s*\(', re.IGNORECASE),
        re.compile(r'\bos\.popen\s*\(', re.IGNORECASE),
        re.compile(r'\bos\.spawn', re.IGNORECASE),
        re.compile(r'\bos\.exec', re.IGNORECASE),
        re.compile(r'\b__import__\s*\(', re.IGNORECASE),
        re.compile(r'\bimportlib\b', re.IGNORECASE),
        re.compile(r'\bcompile\s*\(', re.IGNORECASE),
        re.compile(r'\bexecfile\s*\(', re.IGNORECASE),
        re.compile(r'\bgetattr\s*\(.*__', re.IGNORECASE),
        re.compile(r'\bsetattr\s*\(', re.IGNORECASE),
        re.compile(r'\bdelattr\s*\(', re.IGNORECASE),
        re.compile(r'\b__builtins__\b', re.IGNORECASE),
        re.compile(r'\b__globals__\b', re.IGNORECASE),
        re.compile(r'\bctypes\b', re.IGNORECASE),
        re.compile(r'\bpickle\.loads?\s*\(', re.IGNORECASE),
        re.compile(r'\bmarshal\.loads?\s*\(', re.IGNORECASE),
        re.compile(r'\bcall\s*\(\s*["\']sh["\']', re.IGNORECASE),
        re.compile(r'\bPopen\s*\(', re.IGNORECASE),
    ]

    # PII patterns
    PII_PATTERNS = [
        (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), 'SSN'),
        (re.compile(r'\b\d{3}\.\d{2}\.\d{4}\b'), 'SSN'),
        (re.compile(r'\b4[0-9]{12}(?:[0-9]{3})?\b'), 'Credit Card (Visa)'),
        (re.compile(r'\b5[1-5][0-9]{14}\b'), 'Credit Card (Mastercard)'),
        (re.compile(r'\b3[47][0-9]{13}\b'), 'Credit Card (Amex)'),
        (re.compile(r'\b6(?:011|5[0-9]{2})[0-9]{12}\b'), 'Credit Card (Discover)'),
        (re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'), 'Email Address'),
        (re.compile(r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'), 'Phone Number'),
        (re.compile(r'\b\d{5}(?:-\d{4})?\b'), 'ZIP Code'),
        (re.compile(r'\b(?:passport|passport\s*no\.?|passport\s*number)\s*[:\-]?\s*[A-Z0-9]{6,9}\b', re.IGNORECASE), 'Passport Number'),
        (re.compile(r'\b[A-Z]{1,2}\d{6,8}\b'), 'Passport/ID Number'),
        (re.compile(r'\b\d{2,4}[-/]\d{2}[-/]\d{2,4}\b'), 'Date of Birth'),
        (re.compile(r'\b(?:dob|date\s+of\s+birth)\s*[:\-]?\s*\d', re.IGNORECASE), 'Date of Birth'),
        (re.compile(r'\b\d{9,18}\b'), 'Potential Account Number'),
    ]

    # Harmful/biased content keywords
    HARMFUL_KEYWORDS = [
        re.compile(r'\b(?:kill|murder|assassinate|bomb|explosive|weapon|terrorist|terrorism)\b', re.IGNORECASE),
        re.compile(r'\b(?:hate\s+speech|racial\s+slur|ethnic\s+cleansing)\b', re.IGNORECASE),
        re.compile(r'\b(?:self.harm|suicide\s+method|how\s+to\s+die)\b', re.IGNORECASE),
        re.compile(r'\b(?:child\s+abuse|child\s+exploitation|csam)\b', re.IGNORECASE),
        re.compile(r'\b(?:drug\s+synthesis|synthesize\s+drugs|make\s+meth|cook\s+meth)\b', re.IGNORECASE),
        re.compile(r'\b(?:hack\s+into|bypass\s+security|exploit\s+vulnerability|sql\s+injection)\b', re.IGNORECASE),
        re.compile(r'\b(?:phishing|social\s+engineering\s+attack|credential\s+theft)\b', re.IGNORECASE),
        re.compile(r'\b(?:malware|ransomware|trojan|rootkit|keylogger)\b', re.IGNORECASE),
    ]

    # Sensitive data patterns
    SENSITIVE_DATA_PATTERNS = [
        (re.compile(r'\b(?:password|passwd|pwd)\s*[=:]\s*\S+', re.IGNORECASE), 'Password'),
        (re.compile(r'\b(?:api[_\s]?key|apikey)\s*[=:]\s*\S+', re.IGNORECASE), 'API Key'),
        (re.compile(r'\b(?:secret[_\s]?key|secret)\s*[=:]\s*\S+', re.IGNORECASE), 'Secret Key'),
        (re.compile(r'\b(?:access[_\s]?token|auth[_\s]?token|bearer\s+token)\s*[=:]\s*\S+', re.IGNORECASE), 'Auth Token'),
        (re.compile(r'\b(?:private[_\s]?key)\s*[=:]\s*\S+', re.IGNORECASE), 'Private Key'),
        (re.compile(r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----', re.IGNORECASE), 'Private Key Block'),
        (re.compile(r'\b(?:aws[_\s]?access[_\s]?key[_\s]?id)\s*[=:]\s*[A-Z0-9]{20}', re.IGNORECASE), 'AWS Access Key'),
        (re.compile(r'\b(?:aws[_\s]?secret[_\s]?access[_\s]?key)\s*[=:]\s*\S+', re.IGNORECASE), 'AWS Secret Key'),
        (re.compile(r'\b(?:connection[_\s]?string|db[_\s]?url|database[_\s]?url)\s*[=:]\s*\S+', re.IGNORECASE), 'Database Connection String'),
        (re.compile(r'(?:mysql|postgresql|mongodb|redis|amqp)://[^\s]+', re.IGNORECASE), 'Database URL'),
        (re.compile(r'\b(?:internal[_\s]?ip|intranet)\s*[=:]\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', re.IGNORECASE), 'Internal IP'),
        (re.compile(r'\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'), 'Private IP (10.x)'),
        (re.compile(r'\b192\.168\.\d{1,3}\.\d{1,3}\b'), 'Private IP (192.168.x)'),
        (re.compile(r'\b172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}\b'), 'Private IP (172.x)'),
    ]

    def __init__(self):
        self.validation_count = 0

    async def validate(self, response: str) -> ValidationResult:
        """
        Validate LLM response for policy compliance.

        Aggregates violations from all checks and returns is_valid=False
        with a filtered/redacted response when violations are found.
        """
        self.validation_count += 1

        logger.debug(
            "Response validation requested",
            extra={
                "response_length": len(response),
                "validation_count": self.validation_count
            }
        )

        all_violations = []

        # Check for dynamic code execution primitives
        code_violations = await self._check_code_execution(response)
        all_violations.extend(code_violations)

        # Check for PII leakage
        pii_violations = await self.check_pii_leakage(response)
        all_violations.extend(pii_violations)

        # Check for harmful/biased content
        bias_violations = await self.check_bias(response)
        all_violations.extend(bias_violations)

        # Check for sensitive data leakage
        data_violations = await self.check_data_leakage(response)
        all_violations.extend(data_violations)

        if all_violations:
            logger.warning(
                "LLM response validation failed",
                extra={
                    "violations": all_violations,
                    "validation_count": self.validation_count
                }
            )
            filtered = self._redact_response(response, all_violations)
            return ValidationResult(
                is_valid=False,
                violations=all_violations,
                filtered_response=filtered,
                original_response=response
            )

        return ValidationResult(
            is_valid=True,
            violations=[],
            filtered_response=response,
            original_response=response
        )

    async def _check_code_execution(self, response: str) -> list[str]:
        """
        Check if response contains dynamic code execution primitives.
        """
        violations = []
        for pattern in self.CODE_EXECUTION_PATTERNS:
            if pattern.search(response):
                violations.append(
                    f"Dynamic code execution primitive detected: pattern '{pattern.pattern}'"
                )
        return violations

    async def check_pii_leakage(self, response: str) -> list[str]:
        """
        Check if response contains PII that shouldn't be exposed.
        """
        violations = []
        for pattern, label in self.PII_PATTERNS:
            if pattern.search(response):
                violations.append(f"PII detected in response: {label}")
        return violations

    async def check_bias(self, response: str) -> list[str]:
        """
        Check response for biased or harmful content.
        """
        violations = []
        for pattern in self.HARMFUL_KEYWORDS:
            if pattern.search(response):
                violations.append(
                    f"Harmful or biased content detected: pattern '{pattern.pattern}'"
                )
        return violations

    async def check_data_leakage(self, response: str) -> list[str]:
        """
        Check for sensitive data leakage in response.
        """
        violations = []
        for pattern, label in self.SENSITIVE_DATA_PATTERNS:
            if pattern.search(response):
                violations.append(f"Sensitive data detected in response: {label}")
        return violations

    def _redact_response(self, response: str, violations: list[str]) -> str:
        """
        Redact or replace the response content when violations are found.
        """
        redacted = response

        # Redact PII patterns
        for pattern, label in self.PII_PATTERNS:
            redacted = pattern.sub(f'[REDACTED:{label}]', redacted)

        # Redact sensitive data patterns
        for pattern, label in self.SENSITIVE_DATA_PATTERNS:
            redacted = pattern.sub(f'[REDACTED:{label}]', redacted)

        # Redact code execution primitives
        for pattern in self.CODE_EXECUTION_PATTERNS:
            redacted = pattern.sub('[REDACTED:CODE_EXECUTION]', redacted)

        logger.info(
            "Response redacted due to policy violations",
            extra={"violation_count": len(violations)}
        )

        return redacted