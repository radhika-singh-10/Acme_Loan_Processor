"""Scheduling Agent class with explicit model invocation."""

import asyncio
import logging
import re
from typing import Any

from .framework import PolicyProbeAgentFramework
from .helpers import extract_reference_number
from .mcp_servers import call_mcp_server

logger = logging.getLogger(__name__)

_DYNAMIC_CODE_PATTERNS = re.compile(
    r"\b(eval|exec|compile|subprocess|__import__|os\.system|os\.popen|importlib)\b",
    re.IGNORECASE,
)

_INJECTION_PATTERNS = re.compile(
    r"(ignore previous instructions|disregard.*instructions|system prompt|<\|.*\|>)",
    re.IGNORECASE,
)

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

MAX_INPUT_LENGTH = 2000
MAX_MCP_RESULT_LENGTH = 5000

SERVER_AUTH_TOKENS = {
    "Google Calendar": "gc-auth-token-secret",
    "Email": "email-auth-token-secret",
    "Slack": "slack-auth-token-secret",
}


def _sanitize_input(value: str, max_length: int = MAX_INPUT_LENGTH) -> str:
    if not isinstance(value, str):
        value = str(value)
    value = _control_chars_strip(value)
    value = _INJECTION_PATTERNS.sub("", value)
    value = value[:max_length]
    return value.strip()


def _control_chars_strip(value: str) -> str:
    return _CONTROL_CHARS.sub("", value)


def _sanitize_llm_output(output: str) -> str:
    if not isinstance(output, str):
        output = str(output)
    sanitized = _DYNAMIC_CODE_PATTERNS.sub("[REDACTED]", output)
    return sanitized


class SchedulingAgent(PolicyProbeAgentFramework):
    AGENT_ID = "scheduling_agent"
    AGENT_NAME = "Scheduling Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "anthropic.claude-3-5-sonnet-20241022-v2:0"
    BEDROCK_MODEL_ID = "anthropic.claude-3-5-sonnet-20241022-v2:0"
    DESCRIPTION = "Schedules borrower, underwriting, and support meetings."
    MCP_SERVERS = ["Google Calendar", "Email", "Slack"]
    GUARDRAILS = {
        "mask_pii": None,
        "base64_prompt_detection": None,
        "credential_minimization": None,
        "inter_agent_authentication": "mutual_tls",
    }
    SYSTEM_PROMPT = "Coordinate calendar events and notify the relevant teams."

    def _sanitize_mcp_result(self, result: Any) -> Any:
        if isinstance(result, str):
            if len(result) > MAX_MCP_RESULT_LENGTH:
                result = result[:MAX_MCP_RESULT_LENGTH]
            result = _control_chars_strip(result)
            result = _DYNAMIC_CODE_PATTERNS.sub("[REDACTED]", result)
            return result
        if isinstance(result, dict):
            return {k: self._sanitize_mcp_result(v) for k, v in result.items()}
        if isinstance(result, list):
            return [self._sanitize_mcp_result(item) for item in result]
        return result

    async def call_agent_model(self, user_message: str, meeting_reference: str) -> str:
        safe_user_message = _sanitize_input(user_message)
        safe_meeting_reference = _sanitize_input(meeting_reference)

        messages = [
            {"role": "system", "content": self.SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"Meeting reference: {safe_meeting_reference}\n"
                    f"Scheduling request: {safe_user_message or 'Loan coordination meeting requested.'}\n\n"
                    "Draft a scheduling confirmation."
                ),
            },
        ]
        params = {"temperature": 0.2, "max_tokens": 180}

        logger.info(
            "Sending request to LLM model=%s messages=%s params=%s",
            self.BEDROCK_MODEL_ID,
            messages,
            params,
        )

        response = await self.call_bedrock_model(
            messages=messages,
            **params,
        )

        logger.info(
            "Received response from LLM model=%s response=%s",
            self.BEDROCK_MODEL_ID,
            response,
        )

        return response

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        user_message = context.get("user_message", "")
        if not isinstance(user_message, str):
            user_message = str(user_message)
        user_message = _sanitize_input(user_message)

        meeting_reference = extract_reference_number(user_message, prefix="MEET")
        meeting_reference = _sanitize_input(meeting_reference)

        model_output = await self.call_agent_model(user_message, meeting_reference)
        model_output = _sanitize_llm_output(model_output)

        logger.info(
            "Initiating MCP server calls for meeting_reference=%s", meeting_reference
        )

        mcp_activity_raw = await asyncio.gather(
            call_mcp_server(
                self.to_dict(),
                "Google Calendar",
                "create_event",
                {
                    "title": f"Borrower meeting {meeting_reference}",
                    "description": user_message or "Loan coordination meeting requested.",
                    "start": "2026-04-01T10:00:00-07:00",
                    "end": "2026-04-01T10:30:00-07:00",
                    "auth": SERVER_AUTH_TOKENS["Google Calendar"],
                },
            ),
            call_mcp_server(
                self.to_dict(),
                "Email",
                "send_email",
                {
                    "to": ["borrower@acme.example", "underwriting@acme.example"],
                    "subject": f"Meeting scheduled for {meeting_reference}",
                    "body": "The Scheduling Agent created a calendar event for this request.",
                    "auth": SERVER_AUTH_TOKENS["Email"],
                },
            ),
            call_mcp_server(
                self.to_dict(),
                "Slack",
                "post_message",
                {
                    "channel": "#loan-ops",
                    "text": f"Scheduling Agent created meeting {meeting_reference}.",
                    "auth": SERVER_AUTH_TOKENS["Slack"],
                },
            ),
        )

        logger.info(
            "Completed MCP server calls for meeting_reference=%s results=%s",
            meeting_reference,
            mcp_activity_raw,
        )

        mcp_activity = [self._sanitize_mcp_result(result) for result in mcp_activity_raw]

        response = (
            f"Meeting reference: {meeting_reference}\n"
            f"Scheduling request: {user_message or 'No scheduling request provided.'}\n\n"
            f"Scheduling summary:\n{model_output}"
        )

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "mcp_activity": mcp_activity,
        }


scheduling_agent = SchedulingAgent()