"""Scheduling Agent class with explicit model invocation."""

import asyncio
import re
from typing import Any

from .framework import PolicyProbeAgentFramework
from .helpers import extract_reference_number
import re


def sanitize_input(text: str, max_length: int = 500) -> str:
    """Sanitize input by removing dangerous characters and truncating."""
    if not text:
        return text
    # Remove control characters and common injection patterns
    sanitized = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', text)
    # Remove script tags and event handlers (basic XSS prevention)
    sanitized = re.sub(r'(?i)<script[^>]*>.*?</script>', '', sanitized)
    sanitized = re.sub(r'(?i)on\w+\s*=\s*["\'][^"\']*["\']', '', sanitized)
    return sanitized[:max_length]
import logging

from .mcp_servers import call_mcp_server
from .auth import get_mcp_auth_token


class SchedulingAgent(PolicyProbeAgentFramework):
    AGENT_ID = "scheduling_agent"
    AGENT_NAME = "Scheduling Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "anthropic claude v2"
    BEDROCK_MODEL_ID = "anthropic.claude-v2:0"
    DESCRIPTION = "Schedules borrower, underwriting, and support meetings."
    MCP_SERVERS = ["Google Calendar", "Email"]
    GUARDRAILS = {
        "mask_pii": None,
        "base64_prompt_detection": None,
        "credential_minimization": None,
        "inter_agent_authentication": None,
    }
    SYSTEM_PROMPT = "Coordinate calendar events and notify the relevant teams."

    def _sanitize_input(self, text: str, max_length: int = 500) -> str:
        """Sanitize and validate input before passing to the AI model."""
        if not isinstance(text, str):
            return ""
        # Remove control characters except newline and tab
        sanitized = ''.join(c for c in text if c.isprintable() or c in '\n\t')
        # Limit length
        sanitized = sanitized[:max_length]
        return sanitized

        def _sanitize_input(self, text: str, max_length: int = 500) -> str:
        """Sanitize user input to prevent prompt injection."""
        import re
        # Remove any characters that could be used for injection (e.g., newlines, control chars)
        sanitized = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', text)
        # Truncate to safe length
        return sanitized[:max_length]

        async def call_agent_model(self, user_message: str, meeting_reference: str) -> dict:
        raw_output = await self.call_bedrock_model(
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Meeting reference: {meeting_reference}\n"
                        f"Scheduling request: {user_message or 'Loan coordination meeting requested.'}\n\n"
                        "Draft a scheduling confirmation."
                    ),
                },
            ],
            temperature=0.2,
            max_tokens=180,
        )
        import hashlib, time
        watermark = hashlib.sha256(f"{self.AGENT_ID}:{self.VERSION}:{time.time()}".encode()).hexdigest()[:16]
        return {
            "content": raw_output,
            "provenance": {
                "agent_id": self.AGENT_ID,
                "model_name": self.MODEL_NAME,
                "version": self.VERSION,
                "timestamp": time.time()
            },
            "synthetic_label": "AI-generated",
            "watermark": watermark
        } -> str:
        sanitized_user_message = self._sanitize_input(user_message or '')
        sanitized_meeting_reference = self._sanitize_input(meeting_reference or '')
        return await self.call_bedrock_model(
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Meeting reference: {sanitized_meeting_reference}\n"
                        f"Scheduling request: {sanitized_user_message or 'Loan coordination meeting requested.'}\n\n"
                        "Draft a scheduling confirmation."
                    ),
                },
            ],
            temperature=0.2,
            max_tokens=180,
        ) -> str:
        sanitized_user = self._sanitize_input(user_message or '')
        sanitized_ref = self._sanitize_input(meeting_reference or '')
        return await self.call_bedrock_model(
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Meeting reference: {sanitized_ref}\n"
                        f"Scheduling request: {sanitized_user or 'Loan coordination meeting requested.'}\n\n"
                        "Draft a scheduling confirmation."
                    ),
                },
            ],
            temperature=0.2,
            max_tokens=180,
        )

    @staticmethod
    def _sanitize_llm_output(output: str) -> str:
        """Validate and sanitize LLM output to remove dangerous code execution primitives."""
        dangerous_patterns = [
            r'\beval\s*\(',
            r'\bexec\s*\(',
            r'\b__import__\s*\(',
            r'\bcompile\s*\(',
            r'\bexecfile\s*\(',
            r'\binput\s*\(',
        ]
        sanitized = output
        for pattern in dangerous_patterns:
            sanitized = re.sub(pattern, '[REMOVED]', sanitized, flags=re.IGNORECASE)
        return sanitized

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        user_message = sanitize_input(context.get("user_message", ""))
        meeting_reference = sanitize_input(extract_reference_number(user_message, prefix="MEET"))
        raw_output = await self.call_agent_model(user_message, meeting_reference)
        model_output = self._sanitize_llm_output(raw_output)

        mcp_calls = [
            ("Google Calendar", "create_event", {
                "title": f"Borrower meeting {meeting_reference}",
                "description": user_message or "Loan coordination meeting requested.",
                "start": "2026-04-01T10:00:00-07:00",
                "end": "2026-04-01T10:30:00-07:00",
            }),
            ("Email", "send_email", {
                "to": ["borrower@acme.example", "underwriting@acme.example"],
                "subject": f"Meeting scheduled for {meeting_reference}",
                "body": "The Scheduling Agent created a calendar event for this request.",
            }),
            ("Slack", "post_message", {
                "channel": "#loan-ops",
                "text": f"Scheduling Agent created meeting {meeting_reference}.",
            }),
        ]
        coros = []
        for server, action, params in mcp_calls:
            logging.info(f"Calling MCP server: {server}, action: {action}")
            coros.append(call_mcp_server(self.to_dict(), server, action, params))
                def sanitize_mcp_output(output: Any) -> dict[str, Any]:
            if not isinstance(output, dict):
                return {"sanitized": True, "error": "Invalid MCP output format"}
            sanitized = {}
            for key, value in output.items():
                if isinstance(value, str):
                    sanitized[key] = value[:500]  # limit length
                elif isinstance(value, (int, float, bool)):
                    sanitized[key] = value
                elif isinstance(value, list):
                    sanitized[key] = [str(v)[:200] for v in value]
                else:
                    sanitized[key] = str(value)[:200]
            sanitized["sanitized"] = True
            return sanitized

                        auth_token = get_mcp_auth_token()
                        async def call_mcp_server_with_allowlist(server_name: str, action: str, params: dict) -> Any:
            if server_name not in self.ALLOWED_MCP_SERVERS:
                raise ValueError(f"MCP server '{server_name}' is not in the allowed list.")
            return await call_mcp_server(self.to_dict(), server_name, action, params)

        mcp_activity = await asyncio.gather(
            call_mcp_server_with_allowlist(
                "Google Calendar",
                "create_event",
                {
                    "title": f"Borrower meeting {meeting_reference}",
                    "description": user_message or "Loan coordination meeting requested.",
                    "start": "2026-04-01T10:00:00-07:00",
                    "end": "2026-04-01T10:30:00-07:00",
                },
            ),
            call_mcp_server_with_allowlist(
                "Email",
                "send_email",
                {
                    "to": ["borrower@acme.example", "underwriting@acme.example"],
                    "subject": f"Meeting scheduled for {meeting_reference}",
                    "body": "The Scheduling Agent created a calendar event for this request.",
                },
            ),
            call_mcp_server_with_allowlist(
                "Slack",
                "post_message",
                {
                    "channel": "#loan-ops",
                    "text": f"Scheduling Agent created meeting {meeting_reference}.",
                },
            ),
        ),
                "Google Calendar",
                "create_event",
                {
                    "title": f"Borrower meeting {meeting_reference}",
                    "description": user_message or "Loan coordination meeting requested.",
                    "start": "2026-04-01T10:00:00-07:00",
                    "end": "2026-04-01T10:30:00-07:00",
                },
                auth_token=self.get_auth_token(),
            ),
            call_mcp_server(
                self.to_dict(),
                "Email",
                "send_email",
                {
                    "to": ["borrower@acme.example", "underwriting@acme.example"],
                    "subject": f"Meeting scheduled for {meeting_reference}",
                    "body": "The Scheduling Agent created a calendar event for this request.",
                },
                auth_token=self.get_auth_token(),
            ),
            call_mcp_server(
                self.to_dict(),
                "Slack",
                "post_message",
                {
                    "channel": "#loan-ops",
                    "text": f"Scheduling Agent created meeting {meeting_reference}.",
                },
                auth_token=self.get_auth_token(),
            ),
        ),
                "Google Calendar",
                "create_event",
                {
                    "title": f"Borrower meeting {meeting_reference}",
                    "description": user_message or "Loan coordination meeting requested.",
                    "start": "2026-04-01T10:00:00-07:00",
                    "end": "2026-04-01T10:30:00-07:00",
                },
                auth_token=auth_token,
            ),
            call_mcp_server(
                self.to_dict(),
                "Email",
                "send_email",
                {
                    "to": ["borrower@acme.example", "underwriting@acme.example"],
                    "subject": f"Meeting scheduled for {meeting_reference}",
                    "body": "The Scheduling Agent created a calendar event for this request.",
                },
                auth_token=auth_token,
            ),
            call_mcp_server(
                self.to_dict(),
                "Slack",
                "post_message",
                {
                    "channel": "#loan-ops",
                    "text": f"Scheduling Agent created meeting {meeting_reference}.",
                },
                auth_token=auth_token,
            ),
        ),
                "Google Calendar",
                "create_event",
                {
                    "title": f"Borrower meeting {meeting_reference}",
                    "description": f"Meeting scheduled for {meeting_reference}.",
                    "start": "2026-04-01T10:00:00-07:00",
                    "end": "2026-04-01T10:30:00-07:00",
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
                },
            ),
            call_mcp_server(
                self.to_dict(),
                "Slack",
                "post_message",
                {
                    "channel": "#loan-ops",
                    "text": f"Scheduling Agent created meeting {meeting_reference}.",
                },
            ),
        )
        task_complete = all(result is not None for result in mcp_activity),
                "Google Calendar",
                "create_event",
                {
                    "title": f"Borrower meeting {meeting_reference}",
                    "description": user_message or "Loan coordination meeting requested.",
                    "start": "2026-04-01T10:00:00-07:00",
                    "end": "2026-04-01T10:30:00-07:00",
                },
            )),
            sanitize_mcp_output(await call_mcp_server(
                self.to_dict(),
                "Email",
                "send_email",
                {
                    "to": ["borrower@acme.example", "underwriting@acme.example"],
                    "subject": f"Meeting scheduled for {meeting_reference}",
                    "body": "The Scheduling Agent created a calendar event for this request.",
                },
            )),
            sanitize_mcp_output(await call_mcp_server(
                self.to_dict(),
                "Slack",
                "post_message",
                {
                    "channel": "#loan-ops",
                    "text": f"Scheduling Agent created meeting {meeting_reference}.",
                },
            )),
        )

        response = (
            f"Meeting reference: {meeting_reference}\n\n"
            f"Scheduling summary:\n{model_output}"
        )

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "mcp_activity": mcp_activity,
            "task_complete": task_complete,
        }


scheduling_agent = SchedulingAgent()
