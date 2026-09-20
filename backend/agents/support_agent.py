"""Support Agent class with explicit model invocation."""
# Copyright (c) Lineaje, Inc. All rights reserved.
# Lineaje UnifAI guardrail  version=2.0.0-alpha
def _lineaje_load_gr_client():
    """Lineaje-added: load gr_stub_client.py without a pip dependency."""
    import sys as _s, importlib.util as _ilu
    from pathlib import Path as _P
    n = "_lineaje_gr_stub_client"
    if n in _s.modules: return _s.modules[n]
    h = _P(__file__).resolve().parent
    _cand = next((d / "gr_stub_client.py" for d in [h, *h.parents][:8] if (d / "gr_stub_client.py").is_file()), h / "gr_stub_client.py")
    _spec = _ilu.spec_from_file_location(n, _cand)
    _s.modules[n] = _m = _ilu.module_from_spec(_spec)
    _spec.loader.exec_module(_m); return _m


from typing import Any

from .framework import AcmeLoanAgentFramework
from .helpers import extract_reference_number
from .mock_database import search_support_cases


class SupportAgent(AcmeLoanAgentFramework):
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
        # LINEAJE: enforce() `metadata` at agent->user_interface data_egress — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.); AI_APP_SEC_028 (Do not use LLMs from the organization's disallowed list); AI_APP_SEC_067 (Detect direct string interpolation of untrusted input into LLM prompts). Mask/block; do not remove without review. site_id='site:sha256:2996f8b137ecb9f9b0318fb3f1ab7bac45822f662d098a6662706e7a5fcb3f34'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:2996f8b137ecb9f9b0318fb3f1ab7bac45822f662d098a6662706e7a5fcb3f34', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_006', 'guardrail_id': 'Enforce Approved LLM.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_028', 'guardrail_id': 'Enforce Approved LLM', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_067', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_DAT_SEC_001', 'guardrail_id': 'Use Env Variables', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_IAC_018', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_IAC_023', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_DAT_SEC_027', 'guardrail_id': 'Minimise and redact all outbound AI outputs.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_IAC_031', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_IAC_SEC_020', 'guardrail_id': None, 'policy_version': None}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
        metadata = _gr_client.enforce(_gr_site, metadata, content_type='text/plain')
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
