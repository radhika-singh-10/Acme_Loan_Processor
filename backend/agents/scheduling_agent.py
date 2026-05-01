"""Scheduling Agent class with explicit model invocation."""

import asyncio
import logging
import os
import re
import unicodedata
from typing import Any

from .framework import PolicyProbeAgentFramework
from .helpers import extract_reference_number
from .mcp_servers import call_mcp_server

logger = logging.getLogger(__name__)

_CODE_EXECUTION_PRIMITIVES = re.compile(
    r"\b(eval|exec|subprocess|__import__|compile|execfile|globals|locals|getattr|setattr|delattr|vars|dir|open|input|breakpoint)\s*\(",
    re.IGNORECASE,
)

_MAX_INPUT_LENGTH = 4096
_MAX_MCP_FIELD_LENGTH = 2048


def _sanitize_string(value: str, max_length: int = _MAX_INPUT_LENGTH) -> str:
    """Strip control characters, limit length, and allow only safe printable characters."""
    if not isinstance(value, str):
        value = str(value)
    # Normalize unicode
    value = unicodedata.normalize("NFKC", value)
    # Remove control characters (except newline and tab which are safe)
    value = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]", "", value)
    # Limit length
    value = value[:max_length]
    return value


def _sanitize_llm_output(output: str) -> str:
    """Validate and sanitize LLM output by removing dynamic code execution primitives."""
    if not isinstance(output, str):
        output = str(output)
    if _CODE_EXECUTION_PRIMITIVES.search(output):
        logger.warning("LLM output contained dynamic code execution primitives; sanitizing.")
        output = _CODE_EXECUTION_PRIMITIVES.sub("[REDACTED](", output)
    return output


class SchedulingAgent(PolicyProbeAgentFramework):
    AGENT_ID = "scheduling_agent"
    AGENT_NAME = "Scheduling Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "Amazon Nova Pro"
    BEDROCK_MODEL_ID = "amazon.nova-pro-v1:0"
    DESCRIPTION = "Schedules borrower, underwriting, and support meetings."
    MCP_SERVERS = ["Google Calendar", "Email", "Slack"]
    GUARDRAILS = {
        "mask_pii": None,
        "base64_prompt_detection": None,
        "credential_minimization": None,
        "inter_agent_authentication": "enabled",
    }
    SYSTEM_PROMPT = "Coordinate calendar events and notify the relevant teams."

    # Expected server tokens for MCP server authentication (instruction 9)
    MCP_SERVER_TOKENS = {
        "Google Calendar": os.environ.get("MCP_TOKEN_GOOGLE_CALENDAR", ""),
        "Email": os.environ.get("MCP_TOKEN_EMAIL", ""),
        "Slack": os.environ.get("MCP_TOKEN_SLACK", ""),
    }

    def sanitize_input(self, value: str) -> str:
        """Validate and sanitize user input before passing to model or MCP servers."""
        return _sanitize_string(value, max_length=_MAX_INPUT_LENGTH)

    def _validate_mcp_result(self, server_name: str, result: Any) -> Any:
        """Validate and sanitize each MCP server result before use."""
        if result is None:
            logger.warning("MCP server '%s' returned None result.", server_name)
            return {}
        if isinstance(result, dict):
            sanitized = {}
            for k, v in result.items():
                if isinstance(v, str):
                    sanitized[_sanitize_string(str(k))] = _sanitize_string(v, max_length=_MAX_MCP_FIELD_LENGTH)
                else:
                    sanitized[_sanitize_string(str(k))] = v
            # Verify server token if present in result
            result_token = sanitized.get("server_token", "")
            expected_token = self.MCP_SERVER_TOKENS.get(server_name, "")
            if expected_token and result_token != expected_token:
                logger.error(
                    "MCP server '%s' token mismatch. Authentication failed.", server_name
                )
                raise ValueError(f"MCP server authentication failed for server: {server_name}")
            return sanitized
        if isinstance(result, str):
            return _sanitize_string(result, max_length=_MAX_MCP_FIELD_LENGTH)
        return result

    async def call_agent_model(self, user_message: str, meeting_reference: str) -> str:
        messages = [
            {"role": "system", "content": self.SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"Meeting reference: {meeting_reference}\n"
                    f"Scheduling request: {user_message or 'Loan coordination meeting requested.'}\n\n"
                    "Draft a scheduling confirmation."
                ),
            },
        ]
        logger.info(
            "Sending request to LLM model '%s' with messages: %s",
            self.MODEL_NAME,
            messages,
        )
        response = await self.call_bedrock_model(
            messages=messages,
            temperature=0.2,
            max_tokens=180,
        )
        logger.info(
            "Received response from LLM model '%s': %s",
            self.MODEL_NAME,
            response,
        )
        return response

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        raw_user_message = context.get("user_message", "")
        user_message = self.sanitize_input(raw_user_message)

        meeting_reference = extract_reference_number(user_message, prefix="MEET")
        meeting_reference = _sanitize_string(meeting_reference, max_length=64)

        model_output = await self.call_agent_model(user_message, meeting_reference)
        model_output = _sanitize_llm_output(model_output)

        # Retrieve client auth token for MCP server authentication (instruction 10)
        client_auth_token = os.environ.get("MCP_CLIENT_AUTH_TOKEN", "")

        safe_description = _sanitize_string(
            user_message or "Loan coordination meeting requested.", max_length=_MAX_MCP_FIELD_LENGTH
        )
        safe_email_body = _sanitize_string(
            "The Scheduling Agent created a calendar event for this request.",
            max_length=_MAX_MCP_FIELD_LENGTH,
        )
        safe_slack_text = _sanitize_string(
            f"Scheduling Agent created meeting {meeting_reference}.",
            max_length=_MAX_MCP_FIELD_LENGTH,
        )

        logger.info(
            "Initiating MCP server calls for meeting_reference='%s' with servers: %s",
            meeting_reference,
            self.MCP_SERVERS,
        )

        mcp_activity_raw = await asyncio.gather(
            call_mcp_server(
                self.to_dict(),
                "Google Calendar",
                "create_event",
                {
                    "title": f"Borrower meeting {meeting_reference}",
                    "description": safe_description,
                    "start": "2026-04-01T10:00:00-07:00",
                    "end": "2026-04-01T10:30:00-07:00",
                    "auth_token": client_auth_token,
                },
            ),
            call_mcp_server(
                self.to_dict(),
                "Email",
                "send_email",
                {
                    "to": ["borrower@acme.example", "underwriting@acme.example"],
                    "subject": f"Meeting scheduled for {meeting_reference}",
                    "body": safe_email_body,
                    "auth_token": client_auth_token,
                },
            ),
            call_mcp_server(
                self.to_dict(),
                "Slack",
                "post_message",
                {
                    "channel": "#loan-ops",
                    "text": safe_slack_text,
                    "auth_token": client_auth_token,
                },
            ),
        )

        logger.info(
            "Completed MCP server calls for meeting_reference='%s'. Raw results: %s",
            meeting_reference,
            mcp_activity_raw,
        )

        mcp_servers_order = ["Google Calendar", "Email", "Slack"]
        mcp_activity = []
        for server_name, result in zip(mcp_servers_order, mcp_activity_raw):
            validated = self._validate_mcp_result(server_name, result)
            mcp_activity.append(validated)

        logger.info(
            "Validated MCP server results for meeting_reference='%s': %s",
            meeting_reference,
            mcp_activity,
        )

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