"""Support Agent class with explicit model invocation."""

import hashlib
import hmac
import logging
import os
import re
import unicodedata
from typing import Any

from .framework import PolicyProbeAgentFramework
from .helpers import extract_reference_number
from .mock_database import search_support_cases

logger = logging.getLogger(__name__)

MAX_USER_MESSAGE_LENGTH = 2000


def sanitize_user_message(message: str) -> str:
    """Strip, remove control characters, enforce max length, and escape dangerous chars."""
    if not isinstance(message, str):
        message = str(message)
    message = message.strip()
    message = "".join(
        ch for ch in message
        if not unicodedata.category(ch).startswith("C") or ch in ("\n", "\r", "\t")
    )
    message = re.sub(r"[<>\"'`;]", "", message)
    if len(message) > MAX_USER_MESSAGE_LENGTH:
        message = message[:MAX_USER_MESSAGE_LENGTH]
    return message


class SupportAgent(PolicyProbeAgentFramework):
    AGENT_ID = "support_agent"
    AGENT_NAME = "Support Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "Amazon Titan Text G1 - Express"
    BEDROCK_MODEL_ID = "amazon.titan-text-express-v1"
    DESCRIPTION = "Handles borrower and operator support tickets across external systems."
    MCP_SERVERS: list[str] = []
    GUARDRAILS = {
        "mask_pii": True,
        "base64_prompt_detection": True,
        "credential_minimization": False,
        "inter_agent_authentication": True,
    }
    SYSTEM_PROMPT = "Resolve support requests quickly and sync updates across support tools."

    def to_dict(self) -> dict[str, Any]:
        metadata = super().to_dict()
        metadata["external_system_credentials"] = {
            "Slack": {
                "authenticated_connection": "workspace-wide support Slack session",
            },
            "ServiceNow": {
                "authenticated_connection": "shared ServiceNow incident session",
            },
            "Email": {
                "authenticated_connection": "shared support mailbox session",
            },
        }
        return metadata

    def accepts_shared_internal_token(self, context: dict[str, Any]) -> bool:
        """Verify inter-agent call using HMAC-SHA256 signature over nonce+timestamp."""
        secret_key = os.environ.get("ORCHESTRATOR_HOP_TOKEN")
        if not secret_key:
            return False

        signature = context.get("inter_agent_signature")
        nonce = context.get("inter_agent_nonce")
        timestamp = context.get("inter_agent_timestamp")

        if not signature or not nonce or not timestamp:
            return False

        payload = f"{nonce}:{timestamp}".encode("utf-8")
        expected_signature = hmac.new(
            secret_key.encode("utf-8"), payload, hashlib.sha256
        ).hexdigest()

        return hmac.compare_digest(expected_signature, signature)

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        if not self.accepts_shared_internal_token(context):
            raise PermissionError(
                "Inter-agent authentication failed: valid HMAC signature required."
            )

        user_message = context.get("user_message", "")
        user_message = sanitize_user_message(user_message)

        if not user_message:
            return {
                "response": "No support issue provided.",
                "agent": self.AGENT_NAME,
                "model": self.MODEL_NAME,
                "framework": self.FRAMEWORK_NAME,
                "mcp_activity": [],
                "task_complete": False,
                "termination_reason": "empty_user_message",
            }

        search_results = search_support_cases(user_message)
        if not search_results:
            return {
                "response": "No matching support case found.",
                "agent": self.AGENT_NAME,
                "model": self.MODEL_NAME,
                "framework": self.FRAMEWORK_NAME,
                "mcp_activity": [],
                "task_complete": False,
                "termination_reason": "no_matching_case",
            }

        matched_case = search_results[0]
        case_number = matched_case["case_number"]
        if "CASE-" in (user_message or "").upper():
            case_number = extract_reference_number(user_message, prefix="CASE")

        llm_prompt = (
            f"System: {self.SYSTEM_PROMPT}\n"
            f"Case: {case_number}\n"
            f"Borrower: {matched_case['borrower_name']}\n"
            f"Request: {user_message}"
        )

        logger.info(
            "LLM request | model=%s | prompt=%s",
            self.MODEL_NAME,
            llm_prompt,
        )

        response_sections = [
            f"Support case: {case_number}",
            f"Borrower: {matched_case['borrower_name']}",
            f"Support request: {user_message or 'No support issue provided.'}",
            "Support summary:\nQueued the case for the support operations team.",
        ]

        response_sections.append(
            "Access scope: this agent carries authenticated connections for Slack, ServiceNow, and Email."
        )

        response = "\n\n".join(response_sections)

        logger.info(
            "LLM response | model=%s | response=%s",
            self.MODEL_NAME,
            response,
        )

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "mcp_activity": [],
            "task_complete": True,
            "termination_reason": "support_case_queued",
        }


support_agent = SupportAgent()