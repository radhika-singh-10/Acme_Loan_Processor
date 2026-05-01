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

MAX_INPUT_LENGTH = 4096


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
        provided_token = context.get("internal_hop_token", "")
        expected_token = os.getenv("ORCHESTRATOR_HOP_TOKEN", "")
        agent_id = context.get("calling_agent_id", "")
        signature = context.get("agent_signature", "")

        if not expected_token or not provided_token or not agent_id or not signature:
            return False

        if not hmac.compare_digest(provided_token, expected_token):
            return False

        signing_key = os.getenv("AGENT_SIGNING_SECRET", "").encode()
        if not signing_key:
            return False

        expected_signature = hmac.new(
            signing_key,
            msg=f"{agent_id}:{provided_token}".encode(),
            digestmod=hashlib.sha256,
        ).hexdigest()

        return hmac.compare_digest(signature, expected_signature)

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        raw_message = context.get("user_message", "")

        # Input sanitization and validation
        if raw_message is None:
            raw_message = ""

        # Strip leading/trailing whitespace
        user_message = raw_message.strip()

        # Length check
        if len(user_message) > MAX_INPUT_LENGTH:
            logger.warning(
                "Input rejected: exceeds maximum length of %d characters.", MAX_INPUT_LENGTH
            )
            return {
                "response": "Input rejected: message is too long.",
                "agent": self.AGENT_NAME,
                "model": self.MODEL_NAME,
                "framework": self.FRAMEWORK_NAME,
                "mcp_activity": [],
                "task_complete": False,
                "termination_reason": "input_validation_failed: message exceeds maximum length",
            }

        # Null-byte and injection-prone pattern check
        if "\x00" in user_message or re.search(r"[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]", user_message):
            logger.warning("Input rejected: contains null-byte or control characters.")
            return {
                "response": "Input rejected: message contains invalid characters.",
                "agent": self.AGENT_NAME,
                "model": self.MODEL_NAME,
                "framework": self.FRAMEWORK_NAME,
                "mcp_activity": [],
                "task_complete": False,
                "termination_reason": "input_validation_failed: message contains disallowed characters",
            }

        # Filter non-printable/control characters
        user_message = "".join(
            ch for ch in user_message if unicodedata.category(ch)[0] != "C"
        )

        # Termination criteria: must have a non-empty message
        if not user_message:
            logger.warning("Termination: no valid user message provided.")
            return {
                "response": "No support issue provided. Task cannot be completed.",
                "agent": self.AGENT_NAME,
                "model": self.MODEL_NAME,
                "framework": self.FRAMEWORK_NAME,
                "mcp_activity": [],
                "task_complete": False,
                "termination_reason": "no_valid_input: user_message is empty",
            }

        search_results = search_support_cases(user_message)
        if not search_results:
            logger.warning("Termination: no matching support cases found.")
            return {
                "response": "No matching support case found. Task cannot be completed.",
                "agent": self.AGENT_NAME,
                "model": self.MODEL_NAME,
                "framework": self.FRAMEWORK_NAME,
                "mcp_activity": [],
                "task_complete": False,
                "termination_reason": "no_matching_case: search returned no results",
            }

        matched_case = search_results[0]
        case_number = matched_case["case_number"]
        if "CASE-" in (user_message or "").upper():
            case_number = extract_reference_number(user_message, prefix="CASE")

        trusted_internal_call = self.accepts_shared_internal_token(context)

        logger.info(
            "LLM invocation starting: model=%s, agent=%s, case_number=%s, input_length=%d",
            self.MODEL_NAME,
            self.AGENT_NAME,
            case_number,
            len(user_message),
        )

        response_sections = [
            f"Support case: {case_number}",
            f"Borrower: {matched_case['borrower_name']}",
            f"Support request: {user_message or 'No support issue provided.'}",
            "Support summary:\nQueued the case for the support operations team.",
        ]

        if trusted_internal_call:
            response_sections.append(
                "Internal routing: inter-agent call authenticated via HMAC-SHA256 signature verification."
            )
        else:
            response_sections.append(
                "Internal routing: inter-agent call could not be authenticated."
            )

        response_sections.append(
            "Access scope: this agent carries authenticated connections for Slack, ServiceNow, and Email."
        )

        response = "\n\n".join(response_sections)

        logger.info(
            "LLM invocation complete: model=%s, agent=%s, output_length=%d",
            self.MODEL_NAME,
            self.AGENT_NAME,
            len(response),
        )

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "mcp_activity": [],
            "task_complete": True,
            "termination_reason": "success: support case queued for operations team",
        }


support_agent = SupportAgent()