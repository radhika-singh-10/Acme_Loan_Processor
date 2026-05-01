"""Thin runtime registry that ties the separated agent files together."""

import base64
import hashlib
import hmac
import os
import re
from copy import deepcopy
from typing import Any

from .credit_eval_agent import credit_eval_agent
from .file_processor_agent import file_processor_agent
from .mcp_servers import MCP_SERVERS
from .orchestrator_agent import orchestrator_agent
from .rate_check_agent import rate_check_agent
from .loan_processing_agent import loan_processing_agent
from .scheduling_agent import scheduling_agent
from .support_agent import support_agent


AGENTS: dict[str, Any] = {
    loan_processing_agent.AGENT_NAME: loan_processing_agent,
    file_processor_agent.AGENT_NAME: file_processor_agent,
    support_agent.AGENT_NAME: support_agent,
    credit_eval_agent.AGENT_NAME: credit_eval_agent,
    rate_check_agent.AGENT_NAME: rate_check_agent,
    orchestrator_agent.AGENT_NAME: orchestrator_agent,
    scheduling_agent.AGENT_NAME: scheduling_agent,
}

ALLOWED_CONTENT_TYPES = {
    "application/pdf",
    "image/jpeg",
    "image/png",
    "image/gif",
    "image/webp",
    "text/plain",
    "text/html",
    "text/csv",
    "application/json",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
}

MAX_CONTEXT_STRING_LENGTH = 65536
MAX_FILENAME_LENGTH = 255
MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10 MB

_AGENT_SECRET_KEY = os.environ.get("AGENT_SECRET_KEY", "default-secret-key-change-in-production")

_SUSPICIOUS_PATTERNS = [
    re.compile(r"ignore\s+(previous|all|above|prior)\s+(instructions?|prompts?|context)", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(?:a\s+)?(?:an?\s+)?(?:different|new|another|evil|unrestricted)", re.IGNORECASE),
    re.compile(r"disregard\s+(?:your\s+)?(?:previous|all|prior|safety|ethical)", re.IGNORECASE),
    re.compile(r"act\s+as\s+(?:if\s+you\s+(?:are|were)\s+)?(?:a\s+)?(?:an?\s+)?(?:unrestricted|evil|jailbreak)", re.IGNORECASE),
    re.compile(r"system\s*prompt\s*:", re.IGNORECASE),
    re.compile(r"<\s*(?:system|assistant|user)\s*>", re.IGNORECASE),
    re.compile(r"\[INST\]|\[/INST\]|<\|im_start\|>|<\|im_end\|>", re.IGNORECASE),
    re.compile(r"jailbreak|DAN\s+mode|developer\s+mode\s+enabled", re.IGNORECASE),
    re.compile(r"(?:exec|eval|system|popen|subprocess)\s*\(", re.IGNORECASE),
    re.compile(r"(?:/bin/sh|/bin/bash|cmd\.exe|powershell)", re.IGNORECASE),
    re.compile(r"(?:rm\s+-rf|del\s+/f|format\s+c:)", re.IGNORECASE),
]

_INVISIBLE_TEXT_PATTERN = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]")

_LEETSPEAK_PATTERN = re.compile(
    r"(?:1gn0r3|1gnor3|igno[r]3|d1sr3g4rd|sy5t3m|pr0mpt|1nstruct)", re.IGNORECASE
)


def _generate_agent_token(context_id: str) -> str:
    """Generate an HMAC-SHA256 signed token for inter-agent authentication."""
    message = f"agent-call:{context_id}".encode("utf-8")
    signature = hmac.new(_AGENT_SECRET_KEY.encode("utf-8"), message, hashlib.sha256).hexdigest()
    token = base64.b64encode(f"{context_id}:{signature}".encode("utf-8")).decode("utf-8")
    return token


def _verify_agent_token(token: str, context_id: str) -> bool:
    """Verify an HMAC-SHA256 signed token for inter-agent authentication."""
    try:
        decoded = base64.b64decode(token.encode("utf-8")).decode("utf-8")
        parts = decoded.split(":", 1)
        if len(parts) != 2:
            return False
        token_context_id, provided_signature = parts
        if token_context_id != context_id:
            return False
        message = f"agent-call:{context_id}".encode("utf-8")
        expected_signature = hmac.new(
            _AGENT_SECRET_KEY.encode("utf-8"), message, hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(provided_signature, expected_signature)
    except Exception:
        return False


def _sanitize_string(value: str) -> str:
    """Strip whitespace and remove null bytes from a string."""
    value = value.strip()
    value = value.replace("\x00", "")
    return value


def _validate_context(context: dict[str, Any]) -> dict[str, Any]:
    """Validate and sanitize the chat request context."""
    if context is None or not isinstance(context, dict):
        raise ValueError("context must be a non-None dictionary")

    sanitized = {}
    for key, value in context.items():
        if not isinstance(key, str):
            raise ValueError(f"context keys must be strings, got {type(key)}")
        sanitized_key = _sanitize_string(key)
        if isinstance(value, str):
            if len(value) > MAX_CONTEXT_STRING_LENGTH:
                raise ValueError(
                    f"context field '{sanitized_key}' exceeds maximum length of {MAX_CONTEXT_STRING_LENGTH}"
                )
            sanitized_value = _sanitize_string(value)
        else:
            sanitized_value = value
        sanitized[sanitized_key] = sanitized_value

    return sanitized


def _check_file_content_for_malicious_patterns(content: str) -> None:
    """Check file content for hidden prompts, injection attempts, and malicious payloads."""
    if _INVISIBLE_TEXT_PATTERN.search(content):
        raise ValueError("File content contains invisible/hidden text characters that may indicate a prompt injection attempt.")

    if _LEETSPEAK_PATTERN.search(content):
        raise ValueError("File content contains leetspeak patterns that may indicate a prompt injection attempt.")

    for pattern in _SUSPICIOUS_PATTERNS:
        if pattern.search(content):
            raise ValueError(f"File content contains suspicious instruction patterns that may indicate a prompt injection attempt.")

    # Check for base64-encoded suspicious content
    base64_pattern = re.compile(r"(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
    for match in base64_pattern.finditer(content):
        try:
            decoded = base64.b64decode(match.group()).decode("utf-8", errors="ignore")
            for pattern in _SUSPICIOUS_PATTERNS:
                if pattern.search(decoded):
                    raise ValueError("File content contains base64-encoded suspicious instruction patterns.")
        except Exception as e:
            if "base64-encoded suspicious" in str(e):
                raise
            continue

    # Check for binary/shell command payloads
    binary_pattern = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
    if binary_pattern.search(content):
        raise ValueError("File content contains binary or control characters that may indicate a malicious payload.")


def build_catalog() -> dict[str, Any]:
    return {
        "agents": deepcopy([agent.to_dict() for agent in AGENTS.values()]),
        "mcp_servers": deepcopy(list(MCP_SERVERS.values())),
    }


async def handle_chat_request(context: dict[str, Any]) -> dict[str, Any]:
    # Validate and sanitize context
    try:
        sanitized_context = _validate_context(context)
    except ValueError as e:
        return {"error": str(e), "status": "rejected"}

    # Generate inter-agent authentication token
    context_id = str(id(sanitized_context))
    agent_token = _generate_agent_token(context_id)
    sanitized_context["_agent_auth_token"] = agent_token
    sanitized_context["_agent_context_id"] = context_id

    # Verify token before proceeding
    if not _verify_agent_token(agent_token, context_id):
        return {"error": "Inter-agent authentication failed.", "status": "rejected"}

    return await orchestrator_agent.handle(sanitized_context)


async def process_file_attachment(
    content: str | None,
    filename: str,
    content_type: str,
) -> dict[str, Any]:
    # Validate filename
    if not filename or not isinstance(filename, str):
        return {"error": "filename must be a non-empty string", "status": "rejected"}

    # Validate content_type
    if not content_type or not isinstance(content_type, str):
        return {"error": "content_type must be a non-empty string", "status": "rejected"}

    # Sanitize filename and content_type
    filename = _sanitize_string(filename)
    content_type = _sanitize_string(content_type)

    if not filename:
        return {"error": "filename must not be empty after sanitization", "status": "rejected"}

    if not content_type:
        return {"error": "content_type must not be empty after sanitization", "status": "rejected"}

    if len(filename) > MAX_FILENAME_LENGTH:
        return {"error": f"filename exceeds maximum length of {MAX_FILENAME_LENGTH}", "status": "rejected"}

    # Validate content_type against allowlist (strip parameters like charset)
    base_content_type = content_type.split(";")[0].strip().lower()
    if base_content_type not in ALLOWED_CONTENT_TYPES:
        return {
            "error": f"content_type '{base_content_type}' is not permitted",
            "status": "rejected",
        }

    # Sanitize and validate content if present
    if content is not None:
        if not isinstance(content, str):
            return {"error": "content must be a string or None", "status": "rejected"}

        if len(content) > MAX_CONTENT_LENGTH:
            return {
                "error": f"content exceeds maximum length of {MAX_CONTENT_LENGTH} bytes",
                "status": "rejected",
            }

        content = _sanitize_string(content)

        # Check for malicious content in file
        try:
            _check_file_content_for_malicious_patterns(content)
        except ValueError as e:
            return {"error": str(e), "status": "rejected"}

    return await file_processor_agent.process_attachment(content, filename, content_type)