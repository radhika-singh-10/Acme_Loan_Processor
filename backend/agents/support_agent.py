"""Support Agent class with explicit model invocation."""

import os
from typing import Any
import html

from .framework import PolicyProbeAgentFramework
from .helpers import extract_reference_number
from .mock_database import search_support_cases
import base64
import hashlib
import hmac
import time


def sanitize_message(msg: str) -> str:
    """Sanitize user message to prevent malicious prompt injection."""
    return html.escape(msg, quote=True)


class SupportAgent(PolicyProbeAgentFramework):
    AGENT_ID = "support_agent"
    AGENT_NAME = "Support Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "claude 3.5 sonnet"
    BEDROCK_MODEL_ID = "anthropic.claude-3-5-sonnet-20241022-v2:0"
    DESCRIPTION = "Handles borrower and operator support tickets across external systems."
    MCP_SERVERS: list[str] = ["Slack", "ServiceNow", "Email", "Google Calendar"]
    GUARDRAILS = {
        "mask_pii": True,
        "base64_prompt_detection": True,
        "credential_minimization": False,
        "inter_agent_authentication": False,
    }
    SYSTEM_PROMPT = "Resolve support requests quickly and sync updates across support tools."

    INTERNAL_TOKEN_SECRET = b"change_this_to_a_secure_random_key"
    TOKEN_EXPIRY_SECONDS = 300  # 5 minutes
    ALLOWED_ISSUER = "orchestrator-agent"

    def to_dict(self) -> dict[str, Any]:
        metadata = super().to_dict()
                # Only expose the credential this agent actually needs (Slack).
        metadata["external_system_credentials"] = {
            "Slack": {
                "authenticated_connection": "workspace-wide support Slack session",
            },
        },
            "ServiceNow": {
                "authenticated_connection": "shared ServiceNow incident session",
            },
        }
        return metadata

    def _sanitize_input(self, text: str) -> str:
        """Sanitize user input to prevent injection attacks."""
        import re
        # Remove any non-alphanumeric characters except basic punctuation
        sanitized = re.sub(r'[^\w\s.,!?\-]', '', text)
        # Limit length to 500 characters
        return sanitized[:500]

    def accepts_shared_internal_token(self, context: dict[str, Any]) -> bool:
        # Vulnerability: any caller that forwards this shared hop token is treated
        # as authenticated, with no per-agent verification or signature check.
        return context.get("internal_hop_token") == os.environ.get("INTERNAL_HOP_TOKEN", "")

        async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        # Enforce user authentication
        if "authenticated_user" not in context:
            return {
                "response": "Authentication required. Please provide valid user credentials.",
                "agent": self.AGENT_NAME,
                "model": self.MODEL_NAME,
                "framework": self.FRAMEWORK_NAME,
                "mcp_activity": [],
            }
        user_message = context.get("user_message", "")
        matched_case = search_support_cases(user_message)[0]
        case_number = matched_case["case_number"]
        if "CASE-" in (user_message or "").upper():
            case_number = extract_reference_number(user_message, prefix="CASE")
        trusted_internal_call = self.accepts_shared_internal_token(context)
        response_sections = [
            f"Support case: {case_number}",
            f"Borrower: {matched_case['borrower_name']}",
            f"Support request: {user_message or 'No support issue provided.'}",
            "Support summary:\nQueued the case for the support operations team.",
        ]

        if trusted_internal_call:
            response_sections.append(
                "Internal routing: accepted a shared orchestrator hop token without authenticating the calling agent."
            )
        else:
            response_sections.append(
                "Internal routing: no authenticated inter-agent proof was required before evaluating the handoff."
            )

        response_sections.append(
            "Access scope: this single agent still carries authenticated connections for Slack, ServiceNow, and Email."
        )

        response = "\n\n".join(response_sections)

        # Build decision audit record
        input_hash = hashlib.sha256(user_message.encode()).hexdigest()
        output_hash = hashlib.sha256(response.encode()).hexdigest()
        audit_record = {
            "model_id": self.BEDROCK_MODEL_ID,
            "input_hash": input_hash,
            "output_hash": output_hash,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "principal": context.get("user_id", "unknown"),
        }
        try:
            logging.getLogger(__name__).info("Decision audit record: %s", audit_record)
        except Exception:
            logging.getLogger(__name__).exception("Failed to log decision audit record")

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "mcp_activity": [],
        }
        user_message = context.get("user_message", "")
        # Sanitize and validate user_message before use
        user_message = self._sanitize_input(user_message)
        matched_case = search_support_cases(user_message)[0]
        case_number = matched_case["case_number"]
        if "CASE-" in (user_message or "").upper():
            case_number = extract_reference_number(user_message, prefix="CASE")
        # Minimise output: only last 4 digits of case number, truncated borrower name
        masked_case_number = f"...{case_number[-4:]}" if len(case_number) >= 4 else case_number
        borrower_name = matched_case.get("borrower_name", "")
        truncated_borrower = f"{borrower_name[0]}. {borrower_name.split()[-1]}" if borrower_name and " " in borrower_name else borrower_name
        trusted_internal_call = self.accepts_shared_internal_token(context)
        response_sections = [
            f"Support case: {masked_case_number}",
            f"Borrower: {truncated_borrower}",
            f"Support request: {sanitize_message(user_message) or 'No support issue provided.'}",
            "Support summary:\nQueued the case for the support operations team.",
        ]

        if trusted_internal_call:
            response_sections.append(
                "Internal routing: accepted a shared orchestrator hop token without authenticating the calling agent."
            )
        else:
            response_sections.append(
                "Internal routing: no authenticated inter-agent proof was required before evaluating the handoff."
            )

        response_sections.append(
            "Access scope: this single agent still carries authenticated connections for Slack, ServiceNow, Email, and Google Calendar."
        )

        import re
        sanitized_sections = []
        for section in response_sections:
            # Remove eval/exec primitives and dangerous function calls
            section = re.sub(r'\beval\b', '', section, flags=re.IGNORECASE)
            section = re.sub(r'\bexec\b', '', section, flags=re.IGNORECASE)
            section = re.sub(r'\b__import__\b', '', section, flags=re.IGNORECASE)
            section = re.sub(r'\bos\.system\b', '', section, flags=re.IGNORECASE)
            section = re.sub(r'\bsubprocess\b', '', section, flags=re.IGNORECASE)
            sanitized_sections.append(section)
        response = "\n\n".join(sanitized_sections)

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "mcp_activity": [],
        }


support_agent = SupportAgent()
