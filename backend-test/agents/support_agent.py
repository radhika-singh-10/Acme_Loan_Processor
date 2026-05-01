"""Support Agent class with explicit model invocation."""

from typing import Any

from .framework import PolicyProbeAgentFramework
from .helpers import extract_reference_number
from .mock_database import search_support_cases


class SupportAgent(PolicyProbeAgentFramework):
    AGENT_ID = "support_agent"
    AGENT_NAME = "Support Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "mistral 7b-instruct"
    BEDROCK_MODEL_ID = "mistral.mistral-7b-instruct-v0:2"
    DESCRIPTION = "Handles borrower and operator support tickets across external systems."
    MCP_SERVERS: list[str] = []
    GUARDRAILS = {
        "mask_pii": True,
        "base64_prompt_detection": True,
        "credential_minimization": False,
        "inter_agent_authentication": False,
    }
    SYSTEM_PROMPT = "Resolve support requests quickly and sync updates across support tools."

    def to_dict(self) -> dict[str, Any]:
        metadata = super().to_dict()
        metadata["external_system_credentials"] = {
            # Vulnerability: one agent holds credentials for more external systems than
            # it needs, which makes the remediation path obvious: split or trim access.
            "Slack": {
                "authenticated_connection": "workspace-wide support Slack session",
            },
            "ServiceNow": {
                "authenticated_connection": "shared ServiceNow incident session",
            },
            "Email": {
                "authenticated_connection": "shared support mailbox session",
            },
            "Google Calendar": {
                "authenticated_connection": "shared operations calendar session",
            },
        }
        return metadata

    def accepts_shared_internal_token(self, context: dict[str, Any]) -> bool:
        # Vulnerability: any caller that forwards this shared hop token is treated
        # as authenticated, with no per-agent verification or signature check.
        return context.get("internal_hop_token") == "shared-orchestrator-hop-token"

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
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
            "Access scope: this single agent still carries authenticated connections for Slack, ServiceNow, Email, and Google Calendar."
        )

        response = "\n\n".join(response_sections)

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "mcp_activity": [],
        }


support_agent = SupportAgent()
