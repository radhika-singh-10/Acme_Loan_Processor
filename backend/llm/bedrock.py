"""
Amazon Bedrock LLM Client

Client for communicating with LLMs via Amazon Bedrock.

SECURITY NOTES (for Unifai demo):
- Input sanitization applied before sending to LLM
- Response validation applied
- AWS credential handling could be improved
- No rate limiting
"""

import asyncio
import logging
import os
import re
import unicodedata
from typing import Any, Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError

logger = logging.getLogger(__name__)

# Maximum allowed input length
_MAX_INPUT_LENGTH = 32000

# Prompt injection patterns
_PROMPT_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)", re.IGNORECASE),
    re.compile(r"forget\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(?!a\s+document)", re.IGNORECASE),
    re.compile(r"new\s+instructions?\s*:", re.IGNORECASE),
    re.compile(r"system\s*prompt\s*:", re.IGNORECASE),
    re.compile(r"<\s*system\s*>", re.IGNORECASE),
    re.compile(r"\[\s*system\s*\]", re.IGNORECASE),
    re.compile(r"jailbreak", re.IGNORECASE),
    re.compile(r"dan\s+mode", re.IGNORECASE),
    re.compile(r"developer\s+mode", re.IGNORECASE),
    re.compile(r"override\s+(safety|security|guidelines?|restrictions?)", re.IGNORECASE),
]

# PII patterns for redaction
_PII_PATTERNS = [
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[SSN_REDACTED]"),
    (re.compile(r"\b\d{9}\b"), "[SSN_REDACTED]"),
    (re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b"), "[CC_REDACTED]"),
    (re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"), "[EMAIL_REDACTED]"),
]

# Dynamic code execution primitives to detect in LLM output
_CODE_EXEC_PATTERNS = [
    re.compile(r"\beval\s*\(", re.IGNORECASE),
    re.compile(r"\bexec\s*\(", re.IGNORECASE),
    re.compile(r"\bexecfile\s*\(", re.IGNORECASE),
    re.compile(r"\bcompile\s*\(", re.IGNORECASE),
    re.compile(r"\b__import__\s*\(", re.IGNORECASE),
    re.compile(r"\bsubprocess\s*\.\s*\w*\s*\(.*shell\s*=\s*True", re.IGNORECASE | re.DOTALL),
    re.compile(r"\bos\s*\.\s*system\s*\(", re.IGNORECASE),
    re.compile(r"\bos\s*\.\s*popen\s*\(", re.IGNORECASE),
    re.compile(r"\bgetattr\s*\(.*__", re.IGNORECASE),
    re.compile(r"\bsetattr\s*\(", re.IGNORECASE),
    re.compile(r"\bdelattr\s*\(", re.IGNORECASE),
    re.compile(r"\bglobals\s*\(\s*\)", re.IGNORECASE),
    re.compile(r"\blocals\s*\(\s*\)", re.IGNORECASE),
    re.compile(r"\bvars\s*\(\s*\)", re.IGNORECASE),
    re.compile(r"\bimportlib\b", re.IGNORECASE),
    re.compile(r"\bpickle\s*\.\s*loads?\s*\(", re.IGNORECASE),
    re.compile(r"\bmarshal\s*\.\s*loads?\s*\(", re.IGNORECASE),
    re.compile(r"\bctypes\b", re.IGNORECASE),
]

# Document-specific malicious content patterns
_HIDDEN_PROMPT_PATTERNS = [
    re.compile(r"[\u200b\u200c\u200d\u200e\u200f\ufeff\u00ad]"),  # zero-width / invisible chars
    re.compile(r"(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"),  # base64 blobs
    re.compile(r"\b(?:ignore|disregard|forget|override)\b.{0,50}\b(?:instructions?|prompts?|rules?|guidelines?)\b", re.IGNORECASE),
    re.compile(r"\b(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be|roleplay\s+as)\b", re.IGNORECASE),
    re.compile(r"(?:\/bin\/(?:sh|bash|zsh)|cmd\.exe|powershell)", re.IGNORECASE),
    re.compile(r"(?:rm\s+-rf|del\s+\/[fqs]|format\s+[a-z]:)", re.IGNORECASE),
    re.compile(r"(?:chmod|chown|sudo|su\s+-)\s+", re.IGNORECASE),
    # Leetspeak injection patterns
    re.compile(r"1gn[o0]r[e3]\s+[a4]ll\s+pr[e3]v[i1][o0]u[s5]", re.IGNORECASE),
    re.compile(r"[i1]gn[o0]r[e3].{0,30}[i1]n[s5]truct[i1][o0]n[s5]", re.IGNORECASE),
]


class BedrockClient:
    """
    Client for Amazon Bedrock Runtime.

    Security controls applied:
    - Input sanitization and PII redaction before send
    - Prompt injection detection
    - LLM output validation for dynamic code execution primitives
    - Document content scanning for hidden/malicious prompts
    """

    DEFAULT_MODEL = "amazon.titan-text-express-v1"

    def __init__(
        self,
        model_id: Optional[str] = None,
        region: Optional[str] = None,
    ):
        """
        Initialize the Amazon Bedrock client.

        Args:
            model_id: Amazon Bedrock model ID (defaults to env var)
            region: AWS region for Bedrock Runtime (defaults to env vars)
        """
        self.model_id = model_id or os.getenv("BEDROCK_MODEL_ID") or self.DEFAULT_MODEL
        self.region = region or os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION")
        self.session = (
            boto3.session.Session(region_name=self.region)
            if self.region
            else boto3.session.Session()
        )

        if not (self.region or self.session.region_name):
            logger.warning(
                "Amazon Bedrock region not configured. "
                "Set AWS_REGION or AWS_DEFAULT_REGION."
            )

    def _get_client(self):
        client_region = self.region or self.session.region_name
        if not client_region:
            raise ValueError("AWS region is required for Amazon Bedrock Runtime.")

        return self.session.client("bedrock-runtime", region_name=client_region)

    def _sanitize_and_validate_input(self, text: str) -> str:
        """
        Sanitize and validate a user-supplied input string.

        - Strips null bytes and non-printable control characters
        - Enforces maximum length
        - Detects and rejects prompt injection patterns
        - Redacts common PII patterns (SSNs, credit card numbers, email addresses)

        Args:
            text: Raw input string

        Returns:
            Sanitized string

        Raises:
            ValueError: If the input contains prompt injection patterns or exceeds length limits
        """
        if not isinstance(text, str):
            text = str(text)

        # Strip null bytes
        text = text.replace("\x00", "")

        # Strip non-printable control characters (keep newlines, tabs, carriage returns)
        sanitized_chars = []
        for ch in text:
            cat = unicodedata.category(ch)
            if ch in ("\n", "\r", "\t"):
                sanitized_chars.append(ch)
            elif cat.startswith("C"):
                # Skip control/format/surrogate/private-use characters
                continue
            else:
                sanitized_chars.append(ch)
        text = "".join(sanitized_chars)

        # Enforce length limit
        if len(text) > _MAX_INPUT_LENGTH:
            raise ValueError(
                f"Input exceeds maximum allowed length of {_MAX_INPUT_LENGTH} characters."
            )

        # Detect prompt injection patterns
        for pattern in _PROMPT_INJECTION_PATTERNS:
            if pattern.search(text):
                raise ValueError(
                    "Input rejected: potential prompt injection pattern detected."
                )

        # Redact PII patterns
        for pattern, replacement in _PII_PATTERNS:
            text = pattern.sub(replacement, text)

        return text

    def _sanitize_llm_output(self, content: str) -> str:
        """
        Validate and sanitize LLM output by scanning for dynamic code execution primitives.

        Args:
            content: Raw LLM response text

        Returns:
            Sanitized content with flagged sections replaced

        Raises:
            ValueError: If dangerous code execution patterns are detected
        """
        if not content:
            return content

        for pattern in _CODE_EXEC_PATTERNS:
            if pattern.search(content):
                logger.warning(
                    "LLM output contained dynamic code execution primitive; response blocked."
                )
                raise ValueError(
                    "LLM response rejected: dynamic code execution primitive detected in output."
                )

        return content

    def _sanitize_document_content(self, content: str) -> str:
        """
        Scan document content for hidden prompts, invisible characters, base64-encoded
        prompts, leetspeak, suspicious instruction patterns, and binary/shell commands.

        Args:
            content: Raw document content string

        Returns:
            Content if deemed safe

        Raises:
            ValueError: If malicious content is detected
        """
        if not isinstance(content, str):
            content = str(content)

        for pattern in _HIDDEN_PROMPT_PATTERNS:
            match = pattern.search(content)
            if match:
                logger.warning(
                    "Malicious content detected in document at position %d",
                    match.start(),
                )
                raise ValueError(
                    "Document content rejected: potentially malicious or hidden prompt content detected."
                )

        return content

    async def chat(
        self,
        messages: list[dict[str, Any]],
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 2000,
    ) -> str:
        """
        Send a conversation request to Amazon Bedrock.

        Args:
            messages: List of message dicts with role and content
            model: Override model ID for this request
            temperature: Sampling temperature
            max_tokens: Maximum response tokens

        Returns:
            LLM response text
        """
        active_model = model or self.model_id
        active_region = self.region or self.session.region_name
        if not active_region:
            return "LLM service not configured. Please set AWS_REGION or AWS_DEFAULT_REGION."

        # Sanitize and validate all message content before formatting
        sanitized_messages = []
        for message in messages:
            role = message.get("role", "user")
            content = str(message.get("content", ""))
            try:
                sanitized_content = self._sanitize_and_validate_input(content)
            except ValueError as exc:
                logger.warning("Input sanitization rejected message content: %s", exc)
                return f"Input rejected: {exc}"
            sanitized_messages.append({"role": role, "content": sanitized_content})

        bedrock_messages, system_prompts = self._format_messages(sanitized_messages)

        logger.info(
            "Sending request to Amazon Bedrock",
            extra={
                "model": active_model,
                "region": active_region,
                "message_count": len(sanitized_messages),
                "total_content_length": sum(
                    len(str(message.get("content", ""))) for message in sanitized_messages
                ),
            },
        )

        try:
            response = await asyncio.to_thread(
                self._converse,
                active_model,
                bedrock_messages,
                system_prompts,
                temperature,
                max_tokens,
            )

            content = self._extract_text(response)

            # Validate and sanitize LLM output
            try:
                content = self._sanitize_llm_output(content)
            except ValueError as exc:
                logger.warning("LLM output sanitization blocked response: %s", exc)
                return f"Response blocked: {exc}"

            logger.info(
                "Received response from Amazon Bedrock",
                extra={
                    "response_length": len(content),
                },
            )

            return content

        except NoCredentialsError:
            logger.error("Amazon Bedrock credentials not configured")
            return (
                "LLM service not configured. Please provide AWS credentials "
                "supported by boto3."
            )
        except ClientError as error:
            error_code = error.response.get("Error", {}).get("Code", "Unknown")
            logger.error(f"Amazon Bedrock API error: {error_code}")
            return f"Error communicating with LLM: {error_code}"
        except (BotoCoreError, ValueError) as error:
            logger.error(f"Amazon Bedrock client error: {error}")
            return f"Error: {str(error)}"
        except Exception as error:
            logger.error(f"Amazon Bedrock unexpected error: {error}")
            return f"Error: {str(error)}"

    def _converse(
        self,
        model_id: str,
        messages: list[dict[str, Any]],
        system_prompts: list[dict[str, str]],
        temperature: float,
        max_tokens: int,
    ) -> dict[str, Any]:
        client = self._get_client()

        request: dict[str, Any] = {
            "modelId": model_id,
            "messages": messages,
            "inferenceConfig": {
                "maxTokens": max_tokens,
                "temperature": temperature,
            },
        }
        if system_prompts:
            request["system"] = system_prompts

        return client.converse(**request)

    def _format_messages(
        self,
        messages: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
        bedrock_messages: list[dict[str, Any]] = []
        system_prompts: list[dict[str, str]] = []

        for message in messages:
            role = message.get("role", "user")
            content = str(message.get("content", ""))

            if role == "system":
                system_prompts.append({"text": content})
                continue

            bedrock_role = "assistant" if role == "assistant" else "user"
            bedrock_messages.append(
                {
                    "role": bedrock_role,
                    "content": [{"text": content}],
                }
            )

        return bedrock_messages, system_prompts

    def _extract_text(self, response: dict[str, Any]) -> str:
        content_blocks = response.get("output", {}).get("message", {}).get("content", [])
        text_parts = [
            block["text"]
            for block in content_blocks
            if isinstance(block, dict) and block.get("text")
        ]
        return "\n".join(text_parts).strip()

    async def chat_with_context(
        self,
        user_message: str,
        system_prompt: str,
        context: Optional[str] = None,
    ) -> str:
        """
        Convenience method for chat with system prompt and optional context.
        """
        # Sanitize user_message and context before use
        try:
            user_message = self._sanitize_and_validate_input(user_message)
        except ValueError as exc:
            logger.warning("Input sanitization rejected user_message: %s", exc)
            return f"Input rejected: {exc}"

        if context:
            try:
                context = self._sanitize_and_validate_input(context)
            except ValueError as exc:
                logger.warning("Input sanitization rejected context: %s", exc)
                return f"Input rejected: {exc}"

        messages = [{"role": "system", "content": system_prompt}]

        if context:
            messages.append(
                {
                    "role": "user",
                    "content": f"Context:\n{context}\n\nQuery: {user_message}",
                }
            )
        else:
            messages.append({"role": "user", "content": user_message})

        return await self.chat(messages)

    async def analyze_document(self, content: str) -> str:
        """
        Analyze document content using LLM.

        Document content is scanned for hidden/malicious prompts and sanitized
        before being sent to the LLM.
        """
        # Scan for hidden/malicious content in document
        try:
            content = self._sanitize_document_content(content)
        except ValueError as exc:
            logger.warning("Document content rejected by malicious content scanner: %s", exc)
            raise

        # Sanitize and validate the document content as input
        try:
            content = self._sanitize_and_validate_input(content)
        except ValueError as exc:
            logger.warning("Document content rejected by input sanitizer: %s", exc)
            raise

        return await self.chat_with_context(
            user_message="Please analyze this document and provide a summary.",
            system_prompt="You are a document analyst. Analyze the provided content and summarize key points.",
            context=content,
        )