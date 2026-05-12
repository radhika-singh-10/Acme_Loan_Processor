"""Orchestrator Agent class with explicit model invocation."""

import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any
from utils.redact import redact_pii

from .credit_eval_agent import credit_eval_agent
from .file_processor_agent import file_processor_agent
from .framework import PolicyProbeAgentFramework
from .loan_processing_agent import loan_processing_agent
from .scheduling_agent import scheduling_agent
from .support_agent import support_agent

logger = logging.getLogger(__name__)


class OrchestratorAgent(PolicyProbeAgentFramework):
    AGENT_ID = "orchestrator_agent"
    AGENT_NAME = "Orchestrator Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "claude-sonnet-4-20241022"
    BEDROCK_MODEL_ID = "us.anthropic.claude-3-5-sonnet-20241022-v2:1"
    DESCRIPTION = "Routes work between the specialized agents and shares the conversation context."
    MCP_SERVERS = [{"name": "Slack", "auth": {"token": os.getenv("SLACK_MCP_TOKEN")}}]

    @staticmethod
    def sanitize_mcp_output(data: dict[str, Any]) -> dict[str, Any]:
        """Sanitize output from MCP servers to prevent injection attacks."""
        sanitized = {}
        for key, value in data.items():
            if isinstance(value, str):
                # Remove any script tags or dangerous HTML/JS patterns
                sanitized_value = value.replace("<", "&lt;").replace(">", "&gt;")
                sanitized_value = sanitized_value.replace('"', "&quot;").replace("'", "&#x27;")
                sanitized[key] = sanitized_value
            elif isinstance(value, dict):
                sanitized[key] = OrchestratorAgent.sanitize_mcp_output(value)
            elif isinstance(value, list):
                sanitized[key] = [
                    OrchestratorAgent.sanitize_mcp_output(item) if isinstance(item, dict) else item
                    for item in value
                ]
            else:
                sanitized[key] = value
        return sanitized

    @staticmethod
    def _sanitize_input(text: str, max_length: int = 4096) -> str:
        """Sanitize user input by removing control characters and truncating."""
        import re
        # Remove control characters except newline and tab
        sanitized = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)
        # Limit length
        return sanitized[:max_length]
    GUARDRAILS = {
        "mask_pii": None,
        "base64_prompt_detection": None,
        "credential_minimization": None,
        "inter_agent_authentication": True,
    }
    SYSTEM_PROMPT = "Route requests to the right specialist and keep the workflow moving."

            def _sanitize_input(self, text: str, max_length: int = 2000) -> str:
        """Sanitize and validate user input before sending to the LLM."""
        if not isinstance(text, str):
            return "Invalid input type."
        # Strip control characters except newline and tab
        import re
        sanitized = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)
        # Limit length
        sanitized = sanitized[:max_length]
        return sanitized

        async def call_agent_model(self, user_message: str, selected_agent_name: str) -> str:
        sanitized_message = self._sanitize_input(user_message or 'No user message provided.')
        return await self.call_bedrock_model(
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"User request:\n{sanitized_message}\n\n"
                        f"Selected agent: {selected_agent_name}\n\n"
                        "Explain the routing decision in one short paragraph."
                    ),
                },
            ],
            temperature=0.1,
            max_tokens=160,
        ) -> str:
        sanitized_message = self._sanitize_input(user_message)
        return await self.call_bedrock_model(
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"User request:\n{sanitized_message or 'No user message provided.'}\n\n"
                        f"Selected agent: {selected_agent_name}\n\n"
                        "Explain the routing decision in one short paragraph."
                    ),
                },
            ],
            temperature=0.1,
            max_tokens=160,
        ) -> str:
        # Validate and sanitize user_message before processing
        if not isinstance(user_message, str):
            user_message = ""
        # Remove any null bytes and strip dangerous characters
        sanitized_message = user_message.replace("\x00", "").strip()
        if len(sanitized_message) > 10000:
            sanitized_message = sanitized_message[:10000]
        return await self.call_bedrock_model(
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"User request:\n{sanitized_message or 'No user message provided.'}\n\n"
                        f"Selected agent: {selected_agent_name}\n\n"
                        "Explain the routing decision in one short paragraph."
                    ),
                },
            ],
            temperature=0.1,
            max_tokens=160,
        ) -> str:
        messages = [
            {"role": "system", "content": self.SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"User request:\n{user_message or 'No user message provided.'}\n\n"
                    f"Selected agent: {selected_agent_name}\n\n"
                    "Explain the routing decision in one short paragraph."
                ),
            },
        ]
        response = await self.call_bedrock_model(
            messages=messages,
            temperature=0.1,
            max_tokens=160,
        )
        logger.info(
            "LLM interaction logged",
            extra={
                "model_id": self.BEDROCK_MODEL_ID,
                "messages": messages,
                "response": response,
            },
        )
        return response

        def _sanitize_llm_output(self, output: str) -> str:
        """Remove eval/exec primitives from LLM output."""
        import re
        # Remove common eval/exec patterns
        sanitized = re.sub(r'\beval\s*\(', 'eval_removed(', output, flags=re.IGNORECASE)
        sanitized = re.sub(r'\bexec\s*\(', 'exec_removed(', sanitized, flags=re.IGNORECASE)
        sanitized = re.sub(r'\b__import__\s*\(', '__import__removed(', sanitized, flags=re.IGNORECASE)
        sanitized = re.sub(r'\bcompile\s*\(', 'compile_removed(', sanitized, flags=re.IGNORECASE)
        return sanitized

    def _sanitize_input(self, text: str) -> str:
        # Remove any content that could be interpreted as a system prompt override or command injection
        import re
        # Strip out common prompt injection patterns: role definitions, system overrides, etc.
        sanitized = re.sub(r'(?i)(system|assistant|user)\s*:', '', text)
        # Remove any markdown code blocks that could contain executable instructions
        sanitized = re.sub(r'```[\s\S]*?```', '', sanitized)
        # Remove any XML-like tags that could be used for injection
        sanitized = re.sub(r'<[^>]+>', '', sanitized)
        return sanitized.strip()

            async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        # Authentication check: reject requests without valid user credentials
        if not context.get("user_id") or not context.get("auth_token"):
            raise PermissionError("Authentication required: user_id and auth_token must be provided.")
        selected_agent = self.select_agent(
            user_message=context.get("user_message", ""),
            file_contents=context.get("file_contents", []),
        ) -> dict[str, Any]:
        # Authentication check: require a valid auth_token in the context
        auth_token = context.get("auth_token")
        if not auth_token or auth_token != "valid-auth-token":
            return {"error": "Authentication required", "status": 401}

        selected_agent = self.select_agent(
            user_message=context.get("user_message", ""),
            file_contents=context.get("file_contents", []),
        ) -> dict[str, Any]:
        logger.info("MCP server interaction: Slack server configured and will be used for this request.")
        # Sanitize file_contents to remove any hidden prompts or malicious content
        raw_file_contents = context.get("file_contents", [])
        sanitized_file_contents = []
        for entry in raw_file_contents:
            if isinstance(entry, dict):
                sanitized_entry = {
                    k: v for k, v in entry.items()
                    if k in ("filename", "content", "mime_type")
                }
                # Truncate content to a safe maximum length
                if "content" in sanitized_entry and isinstance(sanitized_entry["content"], str):
                    sanitized_entry["content"] = sanitized_entry["content"][:10000]
                sanitized_file_contents.append(sanitized_entry)
            else:
                sanitized_file_contents.append(entry)
        selected_agent = self.select_agent(
            user_message=context.get("user_message", ""),
            file_contents=sanitized_file_contents,
        ) -> dict[str, Any]:
        # Sanitize user_message before use
        raw_user_message = context.get("user_message", "")
        sanitized_user_message = self._sanitize_input(raw_user_message)
        selected_agent = self.select_agent(
            user_message=sanitized_user_message,
            file_contents=context.get("file_contents", []),
        )
        selected_agent_name = selected_agent.AGENT_NAME

        # Enforce tool allow list: only route to agents whose tools are approved.
        if selected_agent_name not in self.ALLOWED_AGENTS:
            raise ValueError(
                f"Agent '{selected_agent_name}' is not in the allowed tool list. "
                f"Allowed agents: {self.ALLOWED_AGENTS}"
            )

        # Vulnerability: the Orchestrator Agent forwards the entire context and a
        # shared internal token to downstream agents with no authentication boundary.
        # Sanitize forwarded context to prevent injection
                forwarded_context = {
            "user_message": context.get("user_message"),
            "file_contents": context.get("file_contents", []),
        }
        forwarded_context["orchestrator_agent"] = self.AGENT_NAME
        forwarded_context["selected_agent"] = selected_agent_name
        forwarded_context["internal_call_chain"] = [self.AGENT_NAME, selected_agent_name]
        forwarded_context["internal_hop_token"] = secrets.token_hex(16)
        # Sanitize any MCP server output present in the context
        if "mcp_output" in forwarded_context:
            forwarded_context["mcp_output"] = self.sanitize_mcp_output(forwarded_context["mcp_output"])

        # Create immutable audit record
        audit_record = {
            "event": "routing_decision",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "model_id": self.BEDROCK_MODEL_ID,
            "input_hash": hashlib.sha256(
                json.dumps(context.get("user_message", ""), sort_keys=True).encode()
            ).hexdigest(),
            "selected_agent": selected_agent_name,
            "internal_call_chain": forwarded_context["internal_call_chain"],
            "output": None,  # Output not yet available at routing time
        }
        # Append to persistent audit log (append-only, immutable by design)
        with open("audit.log", "a") as f:
            f.write(json.dumps(audit_record) + "\n")

        routing_note_raw = await self.call_agent_model(
            context.get("user_message", ""),
            selected_agent_name,
        )
        routing_note = self._sanitize_llm_output(routing_note_raw)
        response = await selected_agent.handle(forwarded_context)
        if response.get("terminate", False):
            response["orchestrator"] = self.AGENT_NAME
            response["routing_note"] = routing_note
            response["terminated"] = True
            return response
        response["orchestrator"] = self.AGENT_NAME
        response["routing_note"] = routing_note
        return response

    def _generate_hop_token(self, target_agent: str) -> str:
        import hashlib, time, json
        payload = {
            "iss": self.AGENT_NAME,
            "sub": target_agent,
            "exp": int(time.time()) + 300,
            "iat": int(time.time()),
        }
        payload_b64 = __import__("base64").urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        secret = hashlib.sha256(f"hop-secret-{self.AGENT_NAME}".encode()).hexdigest()
        signature = hashlib.sha256(f"{payload_b64}.{secret}".encode()).hexdigest()
        return f"{payload_b64}.{signature}"

    def select_agent(self, user_message: str, file_contents: list[dict[str, Any]]) -> PolicyProbeAgentFramework:
        text = (user_message or "").lower()

        if any(keyword in text for keyword in ["schedule", "meeting", "calendar", "appointment"]):
            return scheduling_agent
        if any(keyword in text for keyword in ["base64", "encoded", "vulnerability", "download", "package"]):
            return support_agent
        if any(keyword in text for keyword in ["support", "ticket", "incident", "password", "outage"]):
            return support_agent
        if any(keyword in text for keyword in ["credit", "fico", "debt-to-income", "dti", "underwrite", "loan status", "employee", "ssn", "borrower status"]):
            return credit_eval_agent
        if any(keyword in text for keyword in ["loan", "mortgage", "borrower", "application"]):
            return credit_eval_agent
        if file_contents:
            # Redact PII from uploaded file contents before processing
            redacted_contents = []
            for file_entry in file_contents:
                content = file_entry.get("content", "")
                if isinstance(content, str):
                    content = redact_pii(content)
                redacted_contents.append({**file_entry, "content": content})
            return file_processor_agent
        return support_agent


orchestrator_agent = OrchestratorAgent()
