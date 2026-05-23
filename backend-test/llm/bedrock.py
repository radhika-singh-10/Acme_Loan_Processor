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
import base64
import logging
import os
import re
from typing import Any, Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError

logger = logging.getLogger(__name__)

# Dangerous dynamic code execution primitives to detect in LLM output
_DANGEROUS_PATTERNS = re.compile(
    r'\b(eval|exec|compile|importlib|__import__|subprocess\.call|subprocess\.run|subprocess\.Popen|os\.system|os\.popen|execfile|execv|execve)\b'
    r'|subprocess\s*\.\s*\w+\s*\(.*shell\s*=\s*True',
    re.IGNORECASE | re.DOTALL,
)

# Prompt injection patterns
_INJECTION_PATTERNS = re.compile(
    r'(ignore\s+(previous|prior|above|all)\s+(instructions?|prompts?|context)|'
    r'disregard\s+(previous|prior|above|all)\s+(instructions?|prompts?|context)|'
    r'forget\s+(previous|prior|above|all)\s+(instructions?|prompts?|context)|'
    r'you\s+are\s+now\s+|act\s+as\s+if\s+|pretend\s+(you\s+are|to\s+be)\s+|'
    r'system\s*:\s*|<\s*system\s*>|<\s*/\s*system\s*>|'
    r'\[\s*system\s*\]|\[\s*inst\s*\]|<\s*inst\s*>)',
    re.IGNORECASE,
)

# PII patterns
_EMAIL_PATTERN = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')
_PHONE_PATTERN = re.compile(r'(\+?1?\s?)?(\(?\d{3}\)?[\s.\-]?)(\d{3}[\s.\-]?\d{4})')
_SSN_PATTERN = re.compile(r'\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b')
_CC_PATTERN = re.compile(r'\b(?:\d[ \-]?){13,16}\b')

# Document malicious content patterns
_HIDDEN_CHARS_PATTERN = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\ufeff]')
_SHELL_COMMANDS_PATTERN = re.compile(
    r'\b(rm\s+-rf|chmod\s+|chown\s+|wget\s+|curl\s+|nc\s+|netcat\s+|bash\s+-[ci]|sh\s+-[ci]|'
    r'python\s+-c|perl\s+-e|ruby\s+-e|powershell\s+-|cmd\.exe|/bin/sh|/bin/bash)\b',
    re.IGNORECASE,
)
_LEETSPEAK_PATTERN = re.compile(r'[i1][g9][n][o0][r3][e3]\s+[a4][l1][l1]', re.IGNORECASE)

MAX_CONTENT_LENGTH = 100_000


def _detect_prompt_injection(text: str) -> bool:
    """Return True if prompt injection patterns are detected."""
    return bool(_INJECTION_PATTERNS.search(text))


def _redact_pii(text: str) -> str:
    """Redact PII from text."""
    text = _EMAIL_PATTERN.sub('[EMAIL REDACTED]', text)
    text = _SSN_PATTERN.sub('[SSN REDACTED]', text)
    text = _CC_PATTERN.sub('[CC REDACTED]', text)
    text = _PHONE_PATTERN.sub('[PHONE REDACTED]', text)
    return text


def _validate_content(text: str) -> str:
    """Validate content length and type."""
    if not isinstance(text, str):
        raise ValueError("Content must be a string.")
    if len(text) > MAX_CONTENT_LENGTH:
        raise ValueError(
            f"Content exceeds maximum allowed length of {MAX_CONTENT_LENGTH} characters."
        )
    return text


def sanitize_input(text: str) -> str:
    """
    Compose all input sanitization steps:
    1. Validate content length/type
    2. Detect and block prompt injection
    3. Redact PII
    """
    text = _validate_content(text)
    if _detect_prompt_injection(text):
        raise ValueError("Potential prompt injection detected in input. Request blocked.")
    text = _redact_pii(text)
    return text


class BedrockClient:
    """
    Client for Amazon Bedrock Runtime.
    """

    DEFAULT_MODEL = "amazon.nova-pro-v1:0"

    def __init__(
        self,
        model_id: Optional[str] = None,
        region: Optional[str] = None,
    ):
        """
        Initialize the Amazon Bedrock client.

        Args:
            model_id: Amazon Bedrock model ID (ignored; always uses approved default)
            region: AWS region for Bedrock Runtime (defaults to env vars)
        """
        self.model_id = self.DEFAULT_MODEL
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

    def _sanitize_llm_output(self, content: str) -> str:
        """
        Scan LLM response text for dangerous dynamic code execution primitives.
        Raises ValueError if any are detected.
        """
        if _DANGEROUS_PATTERNS.search(content):
            raise ValueError(
                "LLM response contains potentially dangerous code execution primitives. "
                "Response blocked for security."
            )
        return content

    def _sanitize_document_content(self, content: str) -> str:
        """
        Check document content for hidden/invisible characters, base64-encoded prompts,
        leetspeak patterns, suspicious shell/binary commands, and prompt-injection keywords.
        Raises ValueError if malicious content is detected.
        """
        if _HIDDEN_CHARS_PATTERN.search(content):
            raise ValueError("Document contains hidden or invisible characters. Upload rejected.")

        # Check for base64-encoded prompts
        b64_candidates = re.findall(r'[A-Za-z0-9+/]{40,}={0,2}', content)
        for candidate in b64_candidates:
            try:
                decoded = base64.b64decode(candidate).decode('utf-8', errors='ignore')
                if _detect_prompt_injection(decoded):
                    raise ValueError("Document contains base64-encoded prompt injection. Upload rejected.")
            except Exception as exc:
                if 'Upload rejected' in str(exc):
                    raise
                pass

        if _LEETSPEAK_PATTERN.search(content):
            raise ValueError("Document contains leetspeak injection patterns. Upload rejected.")

        if _SHELL_COMMANDS_PATTERN.search(content):
            raise ValueError("Document contains suspicious shell or binary commands. Upload rejected.")

        if _detect_prompt_injection(content):
            raise ValueError("Document contains prompt injection keywords. Upload rejected.")

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
            model: Override model ID for this request (ignored; always uses approved default)
            temperature: Sampling temperature
            max_tokens: Maximum response tokens

        Returns:
            LLM response text
        """
        active_model = self.model_id
        active_region = self.region or self.session.region_name
        if not active_region:
            return "LLM service not configured. Please set AWS_REGION or AWS_DEFAULT_REGION."

        bedrock_messages, system_prompts = self._format_messages(messages)

        logger.info(
            "Sending request to Amazon Bedrock",
            extra={
                "model": active_model,
                "region": active_region,
                "message_count": len(messages),
                "total_content_length": sum(
                    len(str(message.get("content", ""))) for message in messages
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
            content = self._sanitize_llm_output(content)

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
        sanitized_user_message = sanitize_input(user_message)
        sanitized_system_prompt = sanitize_input(system_prompt)

        messages = [{"role": "system", "content": sanitized_system_prompt}]

        if context:
            sanitized_context = sanitize_input(context)
            messages.append(
                {
                    "role": "user",
                    "content": f"Context:\n{sanitized_context}\n\nQuery: {sanitized_user_message}",
                }
            )
        else:
            messages.append({"role": "user", "content": sanitized_user_message})

        return await self.chat(messages)

    async def analyze_document(self, content: str) -> str:
        """
        Analyze document content using LLM.
        Document content is sanitized before being sent to the LLM.
        """
        sanitized_content = sanitize_input(content)
        sanitized_content = self._sanitize_document_content(sanitized_content)
        return await self.chat_with_context(
            user_message="Please analyze this document and provide a summary.",
            system_prompt="You are a document analyst. Analyze the provided content and summarize key points.",
            context=sanitized_content,
        )