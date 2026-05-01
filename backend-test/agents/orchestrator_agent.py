"""Orchestrator Agent class with explicit model invocation."""

import base64
import hashlib
import hmac
import logging
import os
import re
import secrets
from typing import Any

from .credit_eval_agent import credit_eval_agent
from .file_processor_agent import file_processor_agent
from .framework import PolicyProbeAgentFramework
from .scheduling_agent import scheduling_agent
from .support_agent import support_agent

logger = logging.getLogger(__name__)

# PII patterns to redact from uploaded file contents
_PII_FILE_PATTERNS: list[tuple[str, str]] = [
    (r"\b\d{3}-\d{2}-\d{4}\b", "[REDACTED_SSN]"),
    (r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b", "[REDACTED_CC]"),
    (r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", "[REDACTED_EMAIL]"),
    (r"\b(?:\+?1[\s\-]?)?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{4}\b", "[REDACTED_PHONE]"),
    (
        r"\b(?:0[1-9]|1[0-2])[/\-](?:0[1-9]|[12]\d|3[01])[/\-](?:19|20)\d{2}\b",
        "[REDACTED_DOB]",
    ),
]

# Singapore PII patterns
_SG_PII_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("NRIC/FIN Number", re.compile(r"\b[STFGM]\d{7}[A-Z]\b", re.IGNORECASE)),
    ("SingPass Identifier", re.compile(r"\bsingpass[_\-\s]?id[:\s]*[\w@.]+\b", re.IGNORECASE)),
    (
        "CPF Account Number",
        re.compile(r"\bcpf[_\-\s]?(?:account|acct|no\.?|number)?[:\s]*\d{6,10}\b", re.IGNORECASE),
    ),
    ("Singapore Phone Number", re.compile(r"\b(?:\+65[\s\-]?)?[689]\d{7}\b")),
    ("Singapore Postal Code", re.compile(r"\bSingapore[,\s]+\d{6}\b", re.IGNORECASE)),
    ("Singapore Passport", re.compile(r"\bE\d{7}[A-Z]\b")),
    ("Singapore Driving Licence", re.compile(r"\bS\d{7}[A-Z]\b")),
]


def _redact_pii_from_text(text: str) -> str:
    for pattern, replacement in _PII_FILE_PATTERNS:
        text = re.sub(pattern, replacement, text)
    return text


def _redact_pii_from_file_contents(file_contents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    redacted: list[dict[str, Any]] = []
    for entry in file_contents:
        clean_entry: dict[str, Any] = {}
        for key, value in entry.items():
            if isinstance(value, str):
                clean_entry[key] = _redact_pii_from_text(value)
            elif isinstance(value, bytes):
                try:
                    decoded = value.decode("utf-8", errors="replace")
                    clean_entry[key] = _redact_pii_from_text(decoded).encode("utf-8")
                except Exception:
                    clean_entry[key] = value
            else:
                clean_entry[key] = value
        redacted.append(clean_entry)
    return redacted


def _redact_sg_pii(text: str) -> tuple[str, list[str]]:
    categories: list[str] = []
    for label, pattern in _SG_PII_PATTERNS:
        redacted, n = pattern.subn(f"[REDACTED:{label}]", text)
        if n:
            categories.append(label)
            text = redacted
    return text, categories


def _sanitise_file_contents(
    file_contents: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[str]]:
    sanitised: list[dict[str, Any]] = []
    all_categories: list[str] = []
    for item in file_contents:
        new_item = dict(item)
        for field in ("content", "text", "body", "data"):
            if isinstance(new_item.get(field), str):
                cleaned, cats = _redact_sg_pii(str(new_item[field]))
                new_item[field] = cleaned
                all_categories.extend(cats)
        sanitised.append(new_item)
    return sanitised, list(dict.fromkeys(all_categories))


def _sanitize_llm_input(value: str, max_length: int = 500) -> str:
    """Strip prompt-injection patterns and enforce length before LLM prompts."""
    if not isinstance(value, str):
        value = str(value)
    value = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", value)
    injection_patterns = [
        r"(?i)(\n|\r)+\s*(human|assistant|system|user|ai|instruction|prompt)\s*:",
        r"<\|im_(start|end|sep)\|>",
        r"(?i)ignore (all )?(previous|prior|above) instructions?",
        r"(?i)disregard (all )?(previous|prior|above) instructions?",
        r"(?i)you are now",
        r"(?i)new (role|persona|instructions?)",
        r"###",
        r"---",
    ]
    for pattern in injection_patterns:
        value = re.sub(pattern, "", value)
    return value[:max_length].strip()


class OrchestratorAgent(PolicyProbeAgentFramework):
    AGENT_ID = "orchestrator_agent"
    AGENT_NAME = "Orchestrator Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "claude-3-5-sonnet"
    BEDROCK_MODEL_ID = "anthropic.claude-3-5-sonnet-20241022-v2:0"
    DESCRIPTION = "Routes work between the specialized agents and shares the conversation context."
    MCP_SERVERS = {
        "Slack": {
            "auth": {
                "type": "bearer",
                "token_env_var": "SLACK_MCP_SERVER_TOKEN",
            },
            "tls": {
                "verify": True,
                "ca_bundle_env_var": "SLACK_MCP_CA_BUNDLE",
            },
        }
    }
    GUARDRAILS = {
        "mask_pii": True,
        "base64_prompt_detection": True,
        "credential_minimization": True,
        "inter_agent_authentication": True,
    }
    SYSTEM_PROMPT = "Route requests to the right specialist and keep the workflow moving."

    _MAX_MESSAGE_LENGTH = 4000
    _CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
    _INJECTION_LINE_RE = re.compile(
        r"(?im)(^\s*(system\s*:|ignore\s+|disregard\s+|forget\s+|override\s+))"
    )

    _INVISIBLE_CHARS_RE = re.compile(
        r"[\u00ad\u200b-\u200f\u202a-\u202e\u2060-\u2064\u206a-\u206f\ufeff]"
    )
    _BASE64_BLOB_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
    _PROMPT_OVERRIDE_RE = re.compile(
        r"(ignore (all |previous |above |prior )?instructions?"
        r"|disregard (all |previous |above |prior )?instructions?"
        r"|you are now"
        r"|new (system |)prompt"
        r"|act as"
        r"|jailbreak"
        r"|do anything now"
        r"|dan mode)",
        re.IGNORECASE,
    )
    _SHELL_CMD_RE = re.compile(
        r"(\$\(|`[^`]+`|\beval\b|\bexec\b|\bos\.system\b|\bsubprocess\b"
        r"|\brm\s+-rf\b|\bcurl\b.*\bsh\b|\bwget\b.*\bsh\b)",
        re.IGNORECASE,
    )
    _LEET_RE = re.compile(r"[4@][a-z0-9]{0,3}[3][a-z0-9]{0,3}[1!|][a-z0-9]{0,3}[0]", re.IGNORECASE)

    _DANGEROUS_PATTERNS = [
        "eval(",
        "exec(",
        "compile(",
        "__import__(",
        "subprocess",
        "os.system",
        "os.popen",
        "importlib",
        "__builtins__",
        "globals(",
        "locals(",
        "vars(",
        "getattr(",
        "setattr(",
        "delattr(",
        "open(",
        "execfile(",
        "input(",
        "__class__",
        "__bases__",
        "__subclasses__",
        "__mro__",
    ]

    def _log_mcp_interaction(self, event: str, details: dict[str, Any]) -> None:
        logger.info(
            "MCP server interaction",
            extra={
                "mcp_servers": list(self.MCP_SERVERS.keys()),
                "event": event,
                **details,
            },
        )

    def sanitize_input(self, user_message: str) -> str:
        if not isinstance(user_message, str):
            raise ValueError("user_message must be a string")
        if len(user_message) > self._MAX_MESSAGE_LENGTH:
            user_message = user_message[: self._MAX_MESSAGE_LENGTH]
        user_message = self._CONTROL_CHAR_RE.sub("", user_message)
        if self._INJECTION_LINE_RE.search(user_message):
            cleaned_lines = [
                line for line in user_message.splitlines() if not self._INJECTION_LINE_RE.match(line)
            ]
            user_message = "\n".join(cleaned_lines)
        return user_message.strip()

    def sanitize_mcp_output(self, mcp_output: Any, server_name: str = "Slack") -> Any:
        if mcp_output is None:
            logger.warning("Received None output from MCP server '%s'", server_name)
            return ""
        if isinstance(mcp_output, str):
            sanitized = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", mcp_output)
            max_length = 8192
            if len(sanitized) > max_length:
                logger.warning(
                    "MCP server '%s' output truncated from %d to %d characters",
                    server_name,
                    len(sanitized),
                    max_length,
                )
                sanitized = sanitized[:max_length]
            return sanitized
        if isinstance(mcp_output, dict):
            return {
                k: self.sanitize_mcp_output(v, server_name)
                for k, v in mcp_output.items()
                if isinstance(k, str)
            }
        if isinstance(mcp_output, list):
            return [self.sanitize_mcp_output(item, server_name) for item in mcp_output]
        if isinstance(mcp_output, (int, float, bool)):
            return mcp_output
        logger.warning(
            "Unexpected type '%s' in MCP server '%s' output; replacing with empty string",
            type(mcp_output).__name__,
            server_name,
        )
        return ""

    def _sanitize_llm_output(self, text: str) -> str:
        if not isinstance(text, str):
            logger.warning("LLM output is not a string; replacing with empty string.")
            return ""
        lowered = text.lower()
        for pattern in self._DANGEROUS_PATTERNS:
            if pattern.lower() in lowered:
                logger.warning(
                    "Dangerous pattern '%s' detected in LLM output; output rejected.",
                    pattern,
                )
                return "[Routing note unavailable: output failed safety validation.]"
        sanitized = "".join(ch for ch in text if ch.isprintable() or ch in ("\n", "\r", "\t"))
        return sanitized

    def _scan_file_contents(self, file_contents: list[dict[str, Any]]) -> None:
        for idx, file_obj in enumerate(file_contents or []):
            raw_text = ""
            if isinstance(file_obj, dict):
                raw_text = str(file_obj.get("content", "") or file_obj.get("text", ""))
            elif isinstance(file_obj, str):
                raw_text = file_obj
            if not raw_text:
                continue
            label = f"file[{idx}]"
            if self._INVISIBLE_CHARS_RE.search(raw_text):
                raise ValueError(
                    f"Malicious content detected in {label}: invisible/zero-width characters found."
                )
            for blob in self._BASE64_BLOB_RE.findall(raw_text):
                try:
                    decoded = base64.b64decode(blob + "==").decode("utf-8", errors="ignore")
                    if self._PROMPT_OVERRIDE_RE.search(decoded) or self._SHELL_CMD_RE.search(decoded):
                        raise ValueError(
                            f"Malicious content detected in {label}: "
                            "base64-encoded prompt injection or shell command found."
                        )
                except Exception as exc:
                    if "Malicious" in str(exc):
                        raise
            if self._PROMPT_OVERRIDE_RE.search(raw_text):
                raise ValueError(
                    f"Malicious content detected in {label}: prompt-override phrase found."
                )
            if self._SHELL_CMD_RE.search(raw_text):
                raise ValueError(
                    f"Malicious content detected in {label}: shell command sequence found."
                )
            if self._LEET_RE.search(raw_text):
                raise ValueError(
                    f"Malicious content detected in {label}: leetspeak obfuscation detected."
                )

    async def call_agent_model(self, user_message: str, selected_agent_name: str) -> str:
        safe_user_message = (
            _sanitize_llm_input(user_message, max_length=500)
            if user_message
            else "No user message provided."
        )
        safe_agent_name = _sanitize_llm_input(selected_agent_name, max_length=100)
        if not safe_agent_name:
            raise ValueError("selected_agent_name is empty or invalid after sanitization.")

        raw_output = await self.call_bedrock_model(
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"User request:\n{safe_user_message}\n\n"
                        f"Selected agent: {safe_agent_name}\n\n"
                        "Explain the routing decision in one short paragraph."
                    ),
                },
            ],
            temperature=0.1,
            max_tokens=160,
        )
        llm_safe = self._sanitize_llm_output(raw_output)
        return self.sanitize_mcp_output(llm_safe, server_name="Slack")

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        self._log_mcp_interaction(
            "request_received",
            {
                "user_message_preview": str(context.get("user_message", ""))[:120],
                "has_file_contents": bool(context.get("file_contents")),
            },
        )

        raw_file_contents: list[dict[str, Any]] = context.get("file_contents", []) or []
        self._scan_file_contents(raw_file_contents)

        pii_redacted = _redact_pii_from_file_contents(raw_file_contents)
        sanitised_file_contents, sg_categories = _sanitise_file_contents(pii_redacted)
        if sg_categories:
            logger.warning(
                "Singapore PII detected and redacted in uploaded file contents before forwarding",
                extra={"pii_categories": sg_categories},
            )

        sanitised_context = dict(context)
        sanitised_context["file_contents"] = sanitised_file_contents

        raw_message = context.get("user_message", "")
        sanitized_message = self.sanitize_input(raw_message)
        sanitised_context["user_message"] = sanitized_message

        selected_agent = self.select_agent(
            user_message=sanitized_message,
            file_contents=sanitised_file_contents,
        )
        selected_agent_name = selected_agent.AGENT_NAME

        forwarded_context = dict(sanitised_context)
        forwarded_context["orchestrator_agent"] = self.AGENT_NAME
        forwarded_context["selected_agent"] = selected_agent_name
        forwarded_context["internal_call_chain"] = [self.AGENT_NAME, selected_agent_name]
        hop_token = secrets.token_hex(32)
        forwarded_context["internal_hop_token"] = hop_token
        hop_secret_str = os.environ.get("INTER_AGENT_SHARED_SECRET", "")
        if not hop_secret_str.strip():
            raise PermissionError(
                "INTER_AGENT_SHARED_SECRET environment variable must be set for inter-agent authentication."
            )
        hop_secret = hop_secret_str.encode()
        hop_signature = hmac.new(
            hop_secret,
            msg=f"{hop_token}:{selected_agent_name}".encode(),
            digestmod=hashlib.sha256,
        ).hexdigest()
        forwarded_context["internal_hop_signature"] = hop_signature

        self._log_mcp_interaction(
            "routing_decision",
            {
                "selected_agent": selected_agent_name,
            },
        )
        logger.info(
            "Orchestrator Agent routing request",
            extra={
                "selected_agent": selected_agent_name,
                "internal_call_chain": forwarded_context["internal_call_chain"],
            },
        )

        logger.info(
            "Orchestrator Agent LLM request",
            extra={
                "user_message": _redact_pii_from_text(sanitized_message),
                "selected_agent_name": selected_agent_name,
            },
        )
        routing_note = await self.call_agent_model(sanitized_message, selected_agent_name)
        logger.info(
            "Orchestrator Agent LLM response",
            extra={
                "routing_note": routing_note,
            },
        )

        verify_secret_str = os.environ.get("INTER_AGENT_SHARED_SECRET", "")
        if not verify_secret_str.strip():
            raise PermissionError(
                "INTER_AGENT_SHARED_SECRET environment variable must be set for inter-agent authentication."
            )
        verify_secret = verify_secret_str.encode()
        expected_sig = hmac.new(
            verify_secret,
            msg=f"{forwarded_context['internal_hop_token']}:{selected_agent_name}".encode(),
            digestmod=hashlib.sha256,
        ).hexdigest()
        provided_sig = str(forwarded_context.get("internal_hop_signature", ""))
        if not hmac.compare_digest(expected_sig, provided_sig):
            logger.error(
                "Inter-agent authentication failed: invalid hop signature",
                extra={"selected_agent": selected_agent_name},
            )
            raise PermissionError(
                f"Inter-agent authentication failed for agent '{selected_agent_name}': "
                "hop token signature mismatch."
            )
        logger.info(
            "Inter-agent authentication succeeded",
            extra={"selected_agent": selected_agent_name},
        )
        logger.info(
            "LLM interaction input",
            extra={
                "forwarded_context_user_message": _redact_pii_from_text(
                    str(forwarded_context.get("user_message", ""))
                ),
                "selected_agent": selected_agent_name,
            },
        )
        raw_agent_result = await selected_agent.handle(forwarded_context)
        logger.info(
            "LLM interaction output",
            extra={
                "raw_agent_result": str(raw_agent_result),
                "selected_agent": selected_agent_name,
            },
        )
        if isinstance(raw_agent_result, dict):
            result = self.sanitize_mcp_output(raw_agent_result, server_name="Slack")
            if not isinstance(result, dict):
                result = {"response": result}
        elif isinstance(raw_agent_result, (str, list)):
            result = {"response": self.sanitize_mcp_output(raw_agent_result, server_name="Slack")}
        else:
            result = {"response": str(raw_agent_result)}

        result["routing_note"] = routing_note
        result["orchestrator"] = self.AGENT_NAME
        return result

    def select_agent(
        self, user_message: str, file_contents: list[dict[str, Any]]
    ) -> PolicyProbeAgentFramework:
        self._scan_file_contents(file_contents)
        text = (user_message or "").lower()

        if any(keyword in text for keyword in ["schedule", "meeting", "calendar", "appointment"]):
            return scheduling_agent
        if any(
            keyword in text for keyword in ["base64", "encoded", "vulnerability", "download", "package"]
        ):
            return support_agent
        if any(
            keyword in text for keyword in ["support", "ticket", "incident", "password", "outage"]
        ):
            return support_agent
        if any(
            keyword in text
            for keyword in [
                "credit",
                "fico",
                "debt-to-income",
                "dti",
                "underwrite",
                "loan status",
                "employee",
                "ssn",
                "borrower status",
            ]
        ):
            return credit_eval_agent
        if any(keyword in text for keyword in ["loan", "mortgage", "borrower", "application"]):
            return credit_eval_agent
        if file_contents:
            return file_processor_agent
        return support_agent


orchestrator_agent = OrchestratorAgent()