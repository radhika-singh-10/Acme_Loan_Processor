"""
PII Detection Module

Detects personally identifiable information in content.

SECURITY NOTES (for Unifai demo):
- scan() method performs actual PII pattern matching
- Nested object traversal implemented
- Configurable patterns supported

AFTER UNIFAI REMEDIATION:
- Regex patterns for SSN, credit cards, phone numbers
- Recursive scanning of nested objects
- Configurable patterns from pii_patterns.yaml
- Support for custom industry-specific patterns
- Singapore-specific PII patterns (NRIC, FIN, SingPass, CPF, etc.)
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class PIIMatch:
    """Represents a single PII match."""
    pii_type: str
    value: str
    location: str
    confidence: float


@dataclass
class PIIDetectionResult:
    """Result of PII detection scan."""
    has_violations: bool
    matches: list[PIIMatch] = field(default_factory=list)
    scanned_content_length: int = 0
    scan_depth: int = 0

    def to_dict(self) -> dict:
        return {
            "has_violations": self.has_violations,
            "matches": [
                {
                    "type": m.pii_type,
                    "value": self._mask_value(m.value),
                    "location": m.location,
                    "confidence": m.confidence
                }
                for m in self.matches
            ],
            "scanned_content_length": self.scanned_content_length,
            "scan_depth": self.scan_depth
        }

    def _mask_value(self, value: str) -> str:
        """Mask PII value for safe display."""
        if len(value) <= 4:
            return "****"
        return value[:2] + "*" * (len(value) - 4) + value[-2:]


class PIIDetector:
    """
    Detects PII in text content and structured data.

    USAGE:
        detector = PIIDetector()
        result = await detector.scan(content)
        if result.has_violations:
            # Handle PII detection
    """

    # PII patterns
    PATTERNS = {
        "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
        "ssn_no_dash": r"\b\d{9}\b",
        "credit_card": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
        "phone_us": r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
        "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        # Singapore-specific PII patterns
        "nric_fin": r"\b[STFGM]\d{7}[A-Z]\b",
        "singpass_id": r"\b[STFGM]\d{7}[A-Z]\b",
        "cpf_account": r"\b\d{3}-\d{5}-\d\b",
        "sg_phone": r"\b(?:\+65[-.\s]?)?[689]\d{7}\b",
        "sg_passport": r"\bE\d{7}[A-Z]\b",
        "uen": r"\b\d{9}[A-Z]\b",
    }

    # Type labels for detected PII
    TYPE_LABELS = {
        "ssn": "Social Security Number",
        "ssn_no_dash": "Social Security Number",
        "credit_card": "Credit Card Number",
        "phone_us": "Phone Number",
        "email": "Email Address",
        "nric_fin": "Singapore NRIC/FIN",
        "singpass_id": "SingPass ID",
        "cpf_account": "CPF Account Number",
        "sg_phone": "Singapore Phone Number",
        "sg_passport": "Singapore Passport Number",
        "uen": "Singapore UEN",
    }

    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the PII detector.

        Args:
            config_path: Path to pii_patterns.yaml
        """
        self.config_path = config_path
        self.custom_patterns = {}
        if config_path:
            self.load_patterns(config_path)

    async def scan(self, content: Any, path: str = "root") -> PIIDetectionResult:
        """
        Scan content for PII.

        Args:
            content: Content to scan (string or nested dict/list)
            path: Current path for nested scanning

        Returns:
            PIIDetectionResult with actual scan results
        """
        content_str = str(content) if content else ""

        logger.debug(
            "PII scan requested",
            extra={
                "content_length": len(content_str),
                "content_type": type(content).__name__,
            }
        )

        if isinstance(content, dict):
            return await self.scan_nested(content, path)
        elif isinstance(content, list):
            return await self.scan_nested(content, path)
        elif isinstance(content, str):
            matches = self._scan_string(content, path)
            return PIIDetectionResult(
                has_violations=len(matches) > 0,
                matches=matches,
                scanned_content_length=len(content),
                scan_depth=0
            )
        else:
            matches = self._scan_string(content_str, path)
            return PIIDetectionResult(
                has_violations=len(matches) > 0,
                matches=matches,
                scanned_content_length=len(content_str),
                scan_depth=0
            )

    async def scan_nested(
        self,
        data: Any,
        current_path: str = "root",
        depth: int = 0,
        max_depth: int = 10
    ) -> PIIDetectionResult:
        """
        Recursively scan nested objects for PII.

        Traverses:
        - Nested dictionaries
        - Lists and arrays
        - Object attributes
        - JSON structures

        Example path: "user.profile.contact.details[0].value"
        """
        all_matches = []
        total_length = 0

        if depth >= max_depth:
            return PIIDetectionResult(
                has_violations=False,
                matches=[],
                scanned_content_length=0,
                scan_depth=depth
            )

        if isinstance(data, dict):
            for key, value in data.items():
                child_path = f"{current_path}.{key}"
                child_result = await self.scan_nested(value, child_path, depth + 1, max_depth)
                all_matches.extend(child_result.matches)
                total_length += child_result.scanned_content_length
        elif isinstance(data, list):
            for index, item in enumerate(data):
                child_path = f"{current_path}[{index}]"
                child_result = await self.scan_nested(item, child_path, depth + 1, max_depth)
                all_matches.extend(child_result.matches)
                total_length += child_result.scanned_content_length
        elif isinstance(data, str):
            matches = self._scan_string(data, current_path)
            all_matches.extend(matches)
            total_length += len(data)
        else:
            text = str(data) if data is not None else ""
            matches = self._scan_string(text, current_path)
            all_matches.extend(matches)
            total_length += len(text)

        return PIIDetectionResult(
            has_violations=len(all_matches) > 0,
            matches=all_matches,
            scanned_content_length=total_length,
            scan_depth=depth
        )

    def _scan_string(self, text: str, path: str) -> list[PIIMatch]:
        """
        Scan a string for PII patterns.
        """
        matches = []

        all_patterns = dict(self.PATTERNS)
        for name, info in self.custom_patterns.items():
            all_patterns[name] = info["pattern"]

        for pii_type, pattern in all_patterns.items():
            label = self.TYPE_LABELS.get(pii_type, pii_type)
            if pii_type in self.custom_patterns:
                label = self.custom_patterns[pii_type].get("label", pii_type)
            for match in re.finditer(pattern, text):
                matches.append(PIIMatch(
                    pii_type=label,
                    value=match.group(),
                    location=path,
                    confidence=0.95
                ))

        return matches

    def load_patterns(self, config_path: str) -> None:
        """
        Load custom PII patterns from configuration.
        """
        logger.debug(f"Pattern loading requested for: {config_path}")
        try:
            import yaml
            with open(config_path, "r") as f:
                config = yaml.safe_load(f)
            if config and "patterns" in config:
                for name, info in config["patterns"].items():
                    self.custom_patterns[name] = {
                        "pattern": info.get("pattern", ""),
                        "label": info.get("label", name)
                    }
        except Exception as e:
            logger.warning(f"Failed to load PII patterns from {config_path}: {e}")

    def add_pattern(self, name: str, pattern: str, label: str) -> None:
        """Add a custom PII pattern."""
        self.custom_patterns[name] = {
            "pattern": pattern,
            "label": label
        }