"""Small agent framework base class used by the Acme Loan Processor agents."""
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


import os
from abc import ABC, abstractmethod
from copy import deepcopy
from typing import Any

from llm.bedrock import BedrockClient
from llm.openai_compatible import OpenAICompatibleClient


class AcmeLoanAgentFramework(ABC):
    """Base class that makes agent metadata and model usage obvious."""

    FRAMEWORK_NAME = "AcmeLoanAgentFramework"
    AGENT_ID = ""
    AGENT_NAME = ""
    VERSION = "1.0.0"
    MODEL_NAME = ""
    BEDROCK_MODEL_ID = ""
    BEDROCK_FALLBACK_MODEL_ID = "amazon.nova-micro-v1:0"
    DESCRIPTION = ""
    MCP_SERVERS: list[str] = []
    GUARDRAILS: dict[str, Any] = {}
    SYSTEM_PROMPT = ""
    IS_ROUTABLE = True
    IS_SCAN_ONLY = False

    def __init__(self):
        self.bedrock_client = BedrockClient()
        self.model_client = OpenAICompatibleClient()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.AGENT_ID,
            "name": self.AGENT_NAME,
            "version": self.VERSION,
            "framework": self.FRAMEWORK_NAME,
            "model": self.MODEL_NAME,
            "bedrock_model_id": self.BEDROCK_MODEL_ID,
            "bedrock_fallback_model_id": self.BEDROCK_FALLBACK_MODEL_ID,
            "description": self.DESCRIPTION,
            "mcp_servers": list(self.MCP_SERVERS),
            "guardrails": deepcopy(self.GUARDRAILS),
            "system_prompt": self.SYSTEM_PROMPT,
            "is_routable": self.IS_ROUTABLE,
            "is_scan_only": self.IS_SCAN_ONLY,
        }

    async def call_bedrock_model(
        self,
        messages: list[dict[str, Any]],
        temperature: float = 0.2,
        max_tokens: int = 350,
    ) -> str:
        deployment_override_model = os.getenv("BEDROCK_MODEL_ID")
        active_model = self.BEDROCK_MODEL_ID

        # Deployment override: force all routable runtime agents onto the same
        # Bedrock model while leaving scan-only agents unchanged for scanners.
        if deployment_override_model and self.IS_ROUTABLE and not self.IS_SCAN_ONLY:
            active_model = deployment_override_model

        primary_response = await self.bedrock_client.chat(
            messages=messages,
            model=active_model,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        if (
            (
                "Error communicating with LLM:" in primary_response
                or primary_response.startswith("LLM service not configured")
                or primary_response.startswith("Error:")
            )
            and self.BEDROCK_FALLBACK_MODEL_ID
        ):
            return await self.bedrock_client.chat(
                messages=messages,
                model=self.BEDROCK_FALLBACK_MODEL_ID,
                temperature=temperature,
                max_tokens=max_tokens,
            )
        # LINEAJE: enforce() `primary_response` at agent->user_interface data_egress — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.); AI_APP_SEC_029 (Agent must validate, sanitize LLM output including for presence of eval or any dynamic code execution primitive in LLM output.); AI_APP_SEC_038 (The AI Model must validate and sanitize any input before processing.). Mask/block; do not remove without review. site_id='site:sha256:02a96104f926b5ba760adc4a8d627afb6db2cf96c818fb412c966629945fdf51'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:02a96104f926b5ba760adc4a8d627afb6db2cf96c818fb412c966629945fdf51', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
        primary_response = _gr_client.enforce(_gr_site, primary_response, content_type='text/plain')
        return primary_response

    @abstractmethod
    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        """Handle a request for this agent."""
