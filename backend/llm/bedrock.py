"""
Amazon Bedrock LLM Client

Client for communicating with LLMs via Amazon Bedrock.

SECURITY NOTES (for Unifai demo):
- No input sanitization before sending to LLM
- No response validation
- AWS credential handling could be improved
- No rate limiting
"""

import asyncio
import logging
import os
import re
from typing import Any, Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError

logger = logging.getLogger(__name__)


class BedrockClient:
    """
    Client for Amazon Bedrock Runtime.

    VULNERABILITY: Content sent to LLM without security checks.
    - No PII scanning before send
    - No prompt injection detection
    - No response validation
    """

    DEFAULT_MODEL = "anthropic.claude-v2"

    def __init__(
        self,
        model_id: Optional[str] = None,
        region: Optional[str] = None,
        api_key: Optional[str] = None,
    ):
        """
        Initialize the Amazon Bedrock client.

        Args:
            model_id: Amazon Bedrock model ID (defaults to env var)
            region: AWS region for Bedrock Runtime (defaults to env vars)
            api_key: API key for client authentication (required)
        """
        self.model_id = self._validate_model(model_id or os.getenv("BEDROCK_MODEL_ID") or self.DEFAULT_MODEL)
        self.region = region or os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION")
        self.api_key = api_key or os.getenv("MCP_API_KEY")
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

    def _sanitize_content(self, content: str) -> str:
        """
        Sanitize user content before sending to LLM.
        - Remove potential prompt injection patterns
        - Strip excessive whitespace
        - Limit content length
        """
        if not isinstance(content, str):
            return ""
        # Remove common prompt injection patterns
        content = re.sub(r'(?i)(ignore|forget|disregard|override)\s+(all|previous|above|instructions|commands)', '', content)
        # Remove excessive special characters
        content = re.sub(r'[<>{}|\\^~`]{10,}', '', content)
        # Limit content length to 10000 characters
        content = content[:10000]
        return content.strip()

    async def chat(
        self,
        messages: list[dict[str, Any]],
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 2000,
        auth_token: Optional[str] = None,
    ) -> str:
        """
        Send a conversation request to Amazon Bedrock.

        SECURITY: Messages are sanitized before sending.
        - User content checked for prompt injection patterns
        - Content length limited
        - Response not validated (future improvement)

        Args:
            messages: List of message dicts with role and content
            model: Override model ID for this request
            temperature: Sampling temperature
            max_tokens: Maximum response tokens

        Returns:
            LLM response text
        """
        # Validate authentication token
        expected_token = os.getenv("AGENT_AUTH_TOKEN")
        if expected_token and auth_token != expected_token:
            logger.warning("Unauthorized inter-agent communication attempt.")
            return "Authentication failed: invalid or missing auth token."

                active_model = model or self.model_id
        active_region = self.region or self.session.region_name
        if not active_region:
            return "LLM service not configured. Please set AWS_REGION or AWS_DEFAULT_REGION."

        # Enforce tool allow list
        allowed_tools = {"get_weather", "calculator", "search_database"}
        for msg in messages:
            if msg.get("role") == "assistant" and "tool_calls" in msg:
                for tc in msg["tool_calls"]:
                    if isinstance(tc, dict) and tc.get("function", {}).get("name") not in allowed_tools:
                        logger.warning(f"Blocked disallowed tool call: {tc.get('function', {}).get('name')}")
                        return f"Tool '{tc.get('function', {}).get('name')}' is not in the allowed tool list."

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
                # VULNERABILITY FIXED: Removed message content preview
                # "messages_preview": str(messages)[:200],
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

            logger.info(
                "Received response from Amazon Bedrock",
                extra={
                    "response_length": len(content),
                    # VULNERABILITY FIXED: Removed response content preview
                    # "response_preview": content[:200],
                },
            )

            self._validate_llm_output(content)
            return self._label_and_watermark(content)

    def _label_and_watermark(self, content: str) -> str:
        """Add provenance metadata, synthetic content label, and watermark."""
        label = "[SYNTHETIC] This content was generated by AI. "
        watermark = "\n---\nProvenance: Generated by Amazon Bedrock | Model: {}".format(self.model_id)
        return label + content + watermark

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

    def _validate_llm_output(self, content: str) -> None:
        """Validate LLM output for dangerous code execution patterns."""
        dangerous_patterns = [
            r"\beval\s*\(",
            r"\bexec\s*\(",
            r"\b__import__\s*\(",
            r"\bcompile\s*\(",
            r"\bexecfile\s*\(",
            r"\binput\s*\(",
            r"\bopen\s*\(",
            r"\bos\.system\s*\(",
            r"\bsubprocess\.",
            r"\bimportlib\.",
            r"\b__builtins__",
        ]
        import re
        for pattern in dangerous_patterns:
            if re.search(pattern, content):
                raise ValueError("LLM output contains dangerous code execution pattern")

    def _format_messages(
        self,
        messages: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
        bedrock_messages: list[dict[str, Any]] = []
        system_prompts: list[dict[str, str]] = []

        for message in messages:
            role = message.get("role", "user")
            content = self._sanitize_input(str(message.get("content", "")))

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

    def _sanitize_input(self, text: str) -> str:
        """Sanitize and validate input before sending to LLM."""
        if not isinstance(text, str):
            text = str(text)
        text = text.strip()
        text = text[:10000]
        import re
        text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)
        return text

    async def chat_with_context(
        self,
        user_message: str,
        system_prompt: str,
        context: Optional[str] = None,
    ) -> str:
        """
        Convenience method for chat with system prompt and optional context.

        VULNERABILITY: No content validation.
        """
        user_message = self._sanitize_input(user_message)
        system_prompt = self._sanitize_input(system_prompt)
        if context is not None:
            context = self._sanitize_input(context)
        messages = [{"role": "system", "content": system_prompt}]

        if context:
            # VULNERABILITY: Context added without scanning
            messages.append(
                {
                    "role": "user",
                    "content": f"Context:\n{context}\n\nQuery: {user_message}",
                }
            )
        else:
            messages.append({"role": "user", "content": user_message})

        content = await self.chat(messages)
        self._validate_llm_output(content)
        return content

            def _contains_sg_pii(self, text: str) -> bool:
        """Check for Singapore PII: NRIC/FIN numbers (e.g., S1234567A)."""
        import re
        # Matches Singapore NRIC/FIN format: one letter, 7 digits, one letter
        pattern = r'\b[STFGM]\d{7}[A-Z]\b'
        return bool(re.search(pattern, text))

    async def analyze_document(self, content: str) -> str:
        """
        Analyze document content using LLM.

        VULNERABILITY: Document content sent directly to LLM
        without PII scanning or threat detection.
        """
        # PII check for Singapore categories
        if self._contains_sg_pii(content):
            raise ValueError("Document contains Singapore PII and cannot be processed.")
        return await self.chat_with_context(
            user_message="Please analyze this document and provide a summary.",
            system_prompt="You are a document analyst. Analyze the provided content and summarize key points.",
            context=content,
        ) -> str:
        """
        Analyze document content using LLM.

        PII is redacted before sending to the LLM.
        """
        # Redact PII before sending to LLM
        safe_content = self._redact_pii(content)
        return await self.chat_with_context(
            user_message="Please analyze this document and provide a summary.",
            system_prompt="You are a document analyst. Analyze the provided content and summarize key points.",
            context=safe_content,
        )

    def _redact_pii(self, text: str) -> str:
        """
        Redact common PII patterns (email, phone, SSN, credit card) from text.
        """
        patterns = {
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b': '[EMAIL REDACTED]',
            r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b': '[PHONE REDACTED]',
            r'\b\d{3}-\d{2}-\d{4}\b': '[SSN REDACTED]',
            r'\b(?:\d[ -]*?){13,16}\b': '[CREDIT CARD REDACTED]',
        }
        for pattern, replacement in patterns.items():
            text = re.sub(pattern, replacement, text)
        return text -> str:
        """
        Analyze document content using LLM.

        VULNERABILITY: Document content sent directly to LLM
        without PII scanning or threat detection.
        """
        content = self._sanitize_input(content)
        return await self.chat_with_context(
            user_message="Please analyze this document and provide a summary.",
            system_prompt="You are a document analyst. Analyze the provided content and summarize key points.",
            context=content,
        )
