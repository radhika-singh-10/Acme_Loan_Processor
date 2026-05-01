"""
Input Sanitizer

Sanitizes user input before processing.
"""

import re
import logging
import unicodedata
import base64
from typing import Any

logger = logging.getLogger(__name__)

MAX_LLM_CONTENT_LENGTH = 50000

PROMPT_INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)",
    r"disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)",
    r"forget\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)",
    r"you\s+are\s+now\s+(?:a\s+)?(?:an?\s+)?\w+",
    r"act\s+as\s+(?:a\s+)?(?:an?\s+)?\w+",
    r"pretend\s+(?:you\s+are|to\s+be)\s+",
    r"new\s+instructions?:",
    r"system\s*:\s*you",
    r"<\s*system\s*>",
    r"\[system\]",
    r"###\s*instruction",
    r"###\s*system",
    r"override\s+(previous\s+)?(instructions?|settings?|rules?)",
    r"jailbreak",
    r"do\s+anything\s+now",
    r"dan\s+mode",
    r"developer\s+mode",
    r"sudo\s+mode",
    r"admin\s+mode",
    r"unrestricted\s+mode",
]

LEETSPEAK_MAP = {
    '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', '@': 'a',
    '$': 's', '!': 'i', '+': 't',
}

SUSPICIOUS_LLM_PATTERNS = [
    r"<\s*prompt\s*>",
    r"\[\s*prompt\s*\]",
    r"<\s*instruction\s*>",
    r"\[\s*instruction\s*\]",
    r"<\s*context\s*>",
    r"<\s*human\s*>",
    r"<\s*assistant\s*>",
    r"<\s*ai\s*>",
    r"<\s*user\s*>",
    r"begin\s+prompt",
    r"end\s+prompt",
    r"start\s+of\s+(new\s+)?instructions?",
]

BINARY_SHELL_PATTERNS = [
    r"(?:^|;|\|)\s*(?:bash|sh|zsh|cmd|powershell|exec|eval|system)\s*[\(\s]",
    r"(?:\/bin\/|\/usr\/bin\/|\/usr\/local\/bin\/)\w+",
    r"\x00|\x01|\x02|\x03|\x04|\x05|\x06|\x07|\x08",
    r"\\x[0-9a-fA-F]{2}",
]


class InputSanitizer:
    """
    Sanitizes user input before processing.
    """

    def __init__(self):
        pass

    def _strip_html_tags(self, text: str) -> str:
        """Strip dangerous HTML and script tags from text."""
        # Remove script tags and their content
        text = re.sub(r'<\s*script[^>]*>.*?<\s*/\s*script\s*>', '', text, flags=re.IGNORECASE | re.DOTALL)
        # Remove style tags and their content
        text = re.sub(r'<\s*style[^>]*>.*?<\s*/\s*style\s*>', '', text, flags=re.IGNORECASE | re.DOTALL)
        # Remove iframe tags
        text = re.sub(r'<\s*iframe[^>]*>.*?<\s*/\s*iframe\s*>', '', text, flags=re.IGNORECASE | re.DOTALL)
        # Remove on* event handlers
        text = re.sub(r'\s+on\w+\s*=\s*["\'][^"\']*["\']', '', text, flags=re.IGNORECASE)
        text = re.sub(r'\s+on\w+\s*=\s*[^\s>]+', '', text, flags=re.IGNORECASE)
        # Remove javascript: protocol
        text = re.sub(r'javascript\s*:', '', text, flags=re.IGNORECASE)
        # Remove vbscript: protocol
        text = re.sub(r'vbscript\s*:', '', text, flags=re.IGNORECASE)
        # Remove data: URIs that could contain scripts
        text = re.sub(r'data\s*:\s*text/html[^"\'>\s]*', '', text, flags=re.IGNORECASE)
        # Remove remaining dangerous tags
        dangerous_tags = ['object', 'embed', 'form', 'input', 'button', 'link', 'meta', 'base']
        for tag in dangerous_tags:
            text = re.sub(r'<\s*/?\s*' + tag + r'[^>]*>', '', text, flags=re.IGNORECASE)
        return text

    def _strip_sql_injection(self, text: str) -> str:
        """Strip SQL injection patterns from text."""
        sql_patterns = [
            r"(?i)(\b(union|select|insert|update|delete|drop|create|alter|exec|execute|xp_|sp_)\b)",
            r"(?i)(--\s*$)",
            r"(?i)(;\s*(drop|delete|update|insert|create|alter)\s)",
            r"(?i)(\bor\b\s+\d+\s*=\s*\d+)",
            r"(?i)(\band\b\s+\d+\s*=\s*\d+)",
            r"(?i)(\/\*.*?\*\/)",
            r"(?i)(\bwaitfor\s+delay\b)",
            r"(?i)(\bsleep\s*\(\s*\d+\s*\))",
            r"(?i)(\bbenchmark\s*\()",
            r"(?i)(\bload_file\s*\()",
            r"(?i)(\binto\s+outfile\b)",
            r"(?i)(\binto\s+dumpfile\b)",
        ]
        for pattern in sql_patterns:
            text = re.sub(pattern, '', text)
        return text

    def _strip_command_injection(self, text: str) -> str:
        """Strip command injection characters and patterns from text."""
        # Remove shell command separators and dangerous characters
        text = re.sub(r'[;&|`$](?!\s*\w+\s*=)', '', text)
        # Remove backtick command substitution
        text = re.sub(r'`[^`]*`', '', text)
        # Remove $() command substitution
        text = re.sub(r'\$\([^)]*\)', '', text)
        # Remove common shell injection patterns
        text = re.sub(r'(?i)\b(wget|curl|nc|netcat|ncat|bash|sh|zsh|python|perl|ruby|php)\s+', '', text)
        # Remove path traversal
        text = re.sub(r'\.\.[/\\]', '', text)
        return text

    def _sanitize_string(self, text: str) -> str:
        """Apply all string sanitization steps."""
        text = self._strip_html_tags(text)
        text = self._strip_sql_injection(text)
        text = self._strip_command_injection(text)
        return text

    async def sanitize(self, input_data: Any) -> Any:
        """
        Sanitize input data by stripping dangerous HTML/script tags,
        SQL injection patterns, and command injection characters.
        Recurses into dicts and lists.
        """
        logger.debug(
            "Sanitization requested",
            extra={
                "input_type": type(input_data).__name__,
                "input_preview": str(input_data)[:100]
            }
        )

        if isinstance(input_data, str):
            return self._sanitize_string(input_data)
        elif isinstance(input_data, dict):
            return {k: await self.sanitize(v) for k, v in input_data.items()}
        elif isinstance(input_data, list):
            return [await self.sanitize(item) for item in input_data]
        else:
            return input_data

    def _decode_leetspeak(self, text: str) -> str:
        """Convert leetspeak characters to their alphabetic equivalents for pattern matching."""
        result = []
        for char in text:
            result.append(LEETSPEAK_MAP.get(char, char))
        return ''.join(result)

    def _is_base64_encoded_prompt(self, text: str) -> bool:
        """Check if text contains base64-encoded prompt injection."""
        # Find potential base64 strings
        b64_pattern = re.compile(r'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})')
        matches = b64_pattern.findall(text)
        for match in matches:
            if len(match) < 8:
                continue
            try:
                decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                decoded_lower = decoded.lower()
                for pattern in PROMPT_INJECTION_PATTERNS:
                    if re.search(pattern, decoded_lower, re.IGNORECASE):
                        return True
                for pattern in SUSPICIOUS_LLM_PATTERNS:
                    if re.search(pattern, decoded_lower, re.IGNORECASE):
                        return True
            except Exception:
                continue
        return False

    def _has_invisible_characters(self, text: str) -> bool:
        """Check for invisible/hidden Unicode characters used to hide prompts."""
        invisible_ranges = [
            (0x200B, 0x200F),  # Zero-width spaces and marks
            (0x2028, 0x202F),  # Line/paragraph separators and format chars
            (0xFEFF, 0xFEFF),  # BOM / zero-width no-break space
            (0x00AD, 0x00AD),  # Soft hyphen
            (0x034F, 0x034F),  # Combining grapheme joiner
            (0x115F, 0x1160),  # Hangul fillers
            (0x17B4, 0x17B5),  # Khmer vowel inherent
            (0x3164, 0x3164),  # Hangul filler
            (0xFFA0, 0xFFA0),  # Halfwidth hangul filler
        ]
        for char in text:
            cp = ord(char)
            for start, end in invisible_ranges:
                if start <= cp <= end:
                    return True
        return False

    def _strip_control_characters(self, text: str) -> str:
        """Remove control characters except for common whitespace."""
        result = []
        for char in text:
            cp = ord(char)
            # Allow tab (9), newline (10), carriage return (13), and printable chars
            if cp in (9, 10, 13) or cp >= 32:
                # Skip invisible Unicode characters
                if not self._has_invisible_characters(char):
                    result.append(char)
        return ''.join(result)

    def _has_binary_or_shell_content(self, text: str) -> bool:
        """Check for binary or shell content in text."""
        for pattern in BINARY_SHELL_PATTERNS:
            if re.search(pattern, text):
                return True
        # Check for high density of non-printable characters
        non_printable = sum(1 for c in text if ord(c) < 32 and ord(c) not in (9, 10, 13))
        if len(text) > 0 and non_printable / len(text) > 0.1:
            return True
        return False

    async def sanitize_for_llm(self, content: str) -> str:
        """
        Sanitize content before sending to LLM.

        Detects and blocks:
        - Hidden prompts and invisible characters
        - Base64-encoded prompt injections
        - Leetspeak prompt injections
        - Suspicious LLM instruction patterns
        - Binary/shell content
        - Prompt injection trigger phrases
        Strips control characters and enforces maximum length.
        Raises ValueError if content is empty after sanitization.
        """
        if not isinstance(content, str):
            content = str(content)

        # Check for invisible/hidden characters
        if self._has_invisible_characters(content):
            logger.warning("Detected invisible characters in LLM input, stripping.")
            content = self._strip_control_characters(content)

        # Check for binary or shell content
        if self._has_binary_or_shell_content(content):
            raise ValueError("Content contains binary or shell content that is not allowed.")

        # Check for base64-encoded prompt injections
        if self._is_base64_encoded_prompt(content):
            raise ValueError("Content contains base64-encoded prompt injection attempt.")

        # Check for prompt injection patterns in original content
        content_lower = content.lower()
        for pattern in PROMPT_INJECTION_PATTERNS:
            if re.search(pattern, content_lower, re.IGNORECASE):
                logger.warning("Detected prompt injection pattern in LLM input.")
                content = re.sub(pattern, '', content, flags=re.IGNORECASE)

        # Check for leetspeak prompt injections
        decoded_leet = self._decode_leetspeak(content_lower)
        for pattern in PROMPT_INJECTION_PATTERNS:
            if re.search(pattern, decoded_leet, re.IGNORECASE):
                raise ValueError("Content contains leetspeak prompt injection attempt.")

        # Check for suspicious LLM instruction patterns
        for pattern in SUSPICIOUS_LLM_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                logger.warning("Detected suspicious LLM instruction pattern in input.")
                content = re.sub(pattern, '', content, flags=re.IGNORECASE)

        # Strip control characters
        content = self._strip_control_characters(content)

        # Strip HTML/script tags
        content = self._strip_html_tags(content)

        # Enforce maximum length
        if len(content) > MAX_LLM_CONTENT_LENGTH:
            logger.warning(
                "LLM content truncated from %d to %d characters",
                len(content), MAX_LLM_CONTENT_LENGTH
            )
            content = content[:MAX_LLM_CONTENT_LENGTH]

        # Raise if empty after sanitization
        if not content.strip():
            raise ValueError("Content is empty after sanitization and cannot be sent to LLM.")

        return content

    async def sanitize_filename(self, filename: str) -> str:
        """
        Sanitize filename to prevent path traversal and injection.
        """
        if not isinstance(filename, str):
            filename = str(filename)

        # Remove path traversal sequences
        filename = re.sub(r'\.\.[/\\]', '', filename)
        filename = re.sub(r'[/\\]', '_', filename)

        # Remove null bytes and control characters
        filename = re.sub(r'[\x00-\x1f\x7f]', '', filename)

        # Remove dangerous characters
        filename = re.sub(r'[<>:"|?*]', '', filename)

        # Remove leading dots (hidden files)
        filename = filename.lstrip('.')

        # Normalize unicode
        filename = unicodedata.normalize('NFC', filename)

        # Limit length
        if len(filename) > 255:
            name, _, ext = filename.rpartition('.')
            if ext:
                filename = name[:255 - len(ext) - 1] + '.' + ext
            else:
                filename = filename[:255]

        if not filename.strip():
            filename = 'sanitized_file'

        return filename

    async def normalize_encoding(self, content: str) -> str:
        """
        Normalize text encoding to prevent encoding-based attacks.
        """
        if not isinstance(content, str):
            try:
                content = content.decode('utf-8', errors='replace')
            except AttributeError:
                content = str(content)

        # Normalize Unicode to NFC form
        content = unicodedata.normalize('NFC', content)

        # Remove or replace problematic Unicode categories
        result = []
        for char in content:
            cat = unicodedata.category(char)
            # Keep letters, numbers, punctuation, symbols, spaces, and common separators
            if cat.startswith(('L', 'N', 'P', 'S', 'Z')) or char in ('\n', '\r', '\t'):
                result.append(char)
            elif cat == 'Cc' and ord(char) in (9, 10, 13):
                # Allow tab, newline, carriage return
                result.append(char)
            # Skip control characters and format characters (Cf, Cc, Co, Cs)

        content = ''.join(result)

        return content