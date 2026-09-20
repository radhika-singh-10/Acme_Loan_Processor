"""Rate Check Agent class with explicit OpenRouter + DeepSeek invocation."""
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


import logging
import os
import re
from typing import Any

from llm.openai_compatible import OpenAICompatibleClient

from .framework import AcmeLoanAgentFramework

logger = logging.getLogger(__name__)


class RateCheckAgent(AcmeLoanAgentFramework):
    AGENT_ID = "rate_check_agent"
    AGENT_NAME = "Rate_Check Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "deepseek/deepseek-chat"
    BEDROCK_MODEL_ID = ""
    DESCRIPTION = "Checks lending-rate questions using DeepSeek through OpenRouter."
    MCP_SERVERS: list[str] = []
    GUARDRAILS = {
        "mask_pii": True,
        "base64_prompt_detection": True,
        "credential_minimization": True,
        "inter_agent_authentication": True,
    }
    SYSTEM_PROMPT = "Answer rate-check questions with short, practical lending-rate guidance."
    IS_ROUTABLE = False

    OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
    # Vulnerability: this model is intentionally left outside the org allow list
    # and on the org block list for the policy demo.
    OPENROUTER_MODEL_NAME = "deepseek/deepseek-chat"

    def __init__(self):
        super().__init__()
        self.openrouter_client = OpenAICompatibleClient(
            base_url=self.OPENROUTER_BASE_URL,
            api_key=os.getenv("OPENROUTER_API_KEY"),
        )

    def to_dict(self) -> dict[str, Any]:
        metadata = super().to_dict()
        metadata["provider"] = "OpenRouter"
        metadata["openrouter_base_url"] = self.OPENROUTER_BASE_URL
        metadata["openrouter_model"] = self.OPENROUTER_MODEL_NAME
        # LINEAJE: enforce() `metadata` at agent->user_interface data_egress — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.); AI_APP_SEC_028 (Do not use LLMs from the organization's disallowed list); AI_APP_SEC_067 (Detect direct string interpolation of untrusted input into LLM prompts). Mask/block; do not remove without review. site_id='site:sha256:0df19c3582f994fd226b63d4b3c50449cc5e39c6b94467c9dc70cc89cfdf4dcd'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:0df19c3582f994fd226b63d4b3c50449cc5e39c6b94467c9dc70cc89cfdf4dcd', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_006', 'guardrail_id': 'Enforce Approved LLM.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_028', 'guardrail_id': 'Enforce Approved LLM', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_067', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_IAC_015', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_IAC_018', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_IAC_023', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_IAC_031', 'guardrail_id': None, 'policy_version': None}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
        metadata = _gr_client.enforce(_gr_site, metadata, content_type='text/plain')
        return metadata

    def sanitize_user_message(self, user_message: str) -> tuple[str, bool]:
        sanitized = (user_message or "").strip() or "No rate request provided."
        suspicious_patterns = [
            re.compile(r"<!--.*?-->", re.DOTALL),
            re.compile(r"[A-Za-z0-9+/=]{24,}"),
            re.compile(r"\b(?:curl|wget|bash|sh|zsh|powershell|cmd\.exe|rm|chmod|python\s+-c|exec|eval|subprocess)\b", re.IGNORECASE),
            re.compile(r"\bc[\W_]*u[\W_]*r[\W_]*l\b", re.IGNORECASE),
            re.compile(r"\bc[4@]rl\b|\bw[6g]et\b|\br[mn]\b", re.IGNORECASE),
        ]

        blocked = False
        for pattern in suspicious_patterns:
            if pattern.search(sanitized):
                blocked = True
                sanitized = pattern.sub("<blocked_unsafe_content>", sanitized)

        return sanitized, blocked

    def sanitize_model_output(self, model_output: str) -> str:
        safe_lines: list[str] = []
        for line in (model_output or "").splitlines():
            if re.search(r"\b(?:eval|exec|subprocess|shell\s*=\s*True|os\.system)\b", line, re.IGNORECASE):
                continue
            safe_lines.append(line)
        return "\n".join(safe_lines).strip() or "Rate summary unavailable."

    async def call_agent_model(self, user_message: str) -> str:
        _lineaje_payload = "Rate check LLM request"
        # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.); AI_APP_SEC_028 (Do not use LLMs from the organization's disallowed list); AI_APP_SEC_067 (Detect direct string interpolation of untrusted input into LLM prompts). Mask/block; do not remove without review. site_id='site:sha256:1c5ab84b3fc1af40ad31a390eda6314849d3834d077e69f40bbf40f23c96917a'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:1c5ab84b3fc1af40ad31a390eda6314849d3834d077e69f40bbf40f23c96917a', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_006', 'guardrail_id': 'Enforce Approved LLM.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_028', 'guardrail_id': 'Enforce Approved LLM', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_067', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_IAC_015', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_IAC_018', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_IAC_023', 'guardrail_id': None, 'policy_version': None}], fail_mode='BLOCK', source_type='agent', destination_type='log')
        _lineaje_payload = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json'))
        logger.info(
            _lineaje_payload,
            extra={
                "agent": self.AGENT_ID,
                "model": self.OPENROUTER_MODEL_NAME,
                "prompt_length": len(user_message or ""),
            },
        )
        model_output = await self.openrouter_client.chat(
            model=self.OPENROUTER_MODEL_NAME,
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Rate check request:\n{user_message or 'No rate request provided.'}\n\n"
                        "Provide a concise rate check summary."
                    ),
                },
            ],
            temperature=0.2,
            max_tokens=220,
        )
        _lineaje_payload = "Rate check LLM response"
        # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.); AI_APP_SEC_028 (Do not use LLMs from the organization's disallowed list); AI_APP_SEC_067 (Detect direct string interpolation of untrusted input into LLM prompts). Mask/block; do not remove without review. site_id='site:sha256:0cb9e2b33fbd67836f82b560578a5c2f4052b3d2c840e150c54d990051d41287'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:0cb9e2b33fbd67836f82b560578a5c2f4052b3d2c840e150c54d990051d41287', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_006', 'guardrail_id': 'Enforce Approved LLM.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_028', 'guardrail_id': 'Enforce Approved LLM', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_067', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_IAC_015', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_IAC_018', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_IAC_023', 'guardrail_id': None, 'policy_version': None}], fail_mode='BLOCK', source_type='agent', destination_type='log')
        _lineaje_payload = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json'))
        logger.info(
            _lineaje_payload,
            extra={
                "agent": self.AGENT_ID,
                "model": self.OPENROUTER_MODEL_NAME,
                "response_length": len(model_output or ""),
            },
        )
        # LINEAJE: enforce() `model_output` at agent->user_interface data_egress — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.); AI_APP_SEC_028 (Do not use LLMs from the organization's disallowed list); AI_APP_SEC_067 (Detect direct string interpolation of untrusted input into LLM prompts). Mask/block; do not remove without review. site_id='site:sha256:896092e51e52bd5287264ae5a196b0ac5a928f9aa60eb5890cbd5fb0b8f81ce0'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:896092e51e52bd5287264ae5a196b0ac5a928f9aa60eb5890cbd5fb0b8f81ce0', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_006', 'guardrail_id': 'Enforce Approved LLM.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_028', 'guardrail_id': 'Enforce Approved LLM', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_067', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_IAC_015', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_IAC_018', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_IAC_023', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_IAC_031', 'guardrail_id': None, 'policy_version': None}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
        model_output = _gr_client.enforce(_gr_site, model_output, content_type='text/plain')
        return model_output

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        user_message = context.get("user_message", "")
        safe_user_message, blocked_unsafe_content = self.sanitize_user_message(user_message)
        prompt_message = safe_user_message
        if blocked_unsafe_content:
            prompt_message = (
                "A rate-check request contained blocked unsafe prompt content. "
                "Use only the remaining safe request details."
            )

        model_output = self.sanitize_model_output(await self.call_agent_model(prompt_message))

        response = (
            f"Rate check request: {safe_user_message}\n\n"
            f"Rate summary:\n{model_output}"
        )

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "provider": "OpenRouter",
        }


rate_check_agent = RateCheckAgent()
