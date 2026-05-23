"""Central MCP server catalog and call helpers for PolicyProbe."""

import asyncio
import hashlib
import hmac
import json
import logging
import os
from typing import Any
from uuid import uuid4

import requests

logger = logging.getLogger(__name__)

MCP_BASE_URL = os.getenv("MCP_BASE_URL", "http://127.0.0.1:5500/mock-mcp")
MCP_SHARED_SECRET = os.getenv("MCP_SHARED_SECRET", "changeme-shared-secret")

MAX_STRING_LENGTH = 4096
MAX_BODY_SIZE = 1_048_576  # 1 MB

#vdbv djbmv d,bmfd,
#dfmnbfmnb fkdjfkjd
MCP_SERVERS: dict[str, dict[str, Any]] = {
    "Slack": {
        "name": "Slack",
        "server_key": "slack",
        "version": "1.0.0",
        "description": "Slack workspace messaging for agent alerts and coordination.",
        "transport": "streamable-http",
        "endpoint": f"{MCP_BASE_URL}/slack",
        "tools": {
            "post_message": "slack.post_message",
            "download_demo_package": "slack.download_demo_package",
        },
        "default_headers": {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        },
        "timeout_seconds": 8,
    },
    "ServiceNow": {
        "name": "ServiceNow",
        "server_key": "servicenow",
        "version": "1.0.0",
        "description": "ServiceNow incident and case management for support workflows.",
        "transport": "streamable-http",
        "endpoint": f"{MCP_BASE_URL}/servicenow",
        "tools": {
            "create_incident": "servicenow.create_incident",
        },
        "default_headers": {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        },
        "timeout_seconds": 8,
    },
    "Email": {
        "name": "Email",
        "server_key": "email",
        "version": "1.0.0",
        "description": "Email delivery for borrower communication and status updates.",
        "transport": "streamable-http",
        "endpoint": f"{MCP_BASE_URL}/email",
        "tools": {
            "send_email": "email.send_message",
        },
        "default_headers": {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        },
        "timeout_seconds": 8,
    },
    "Excel": {
        "name": "Excel",
        "server_key": "excel",
        "version": "1.0.0",
        "description": "Excel workbook updates for pipeline tracking and credit worksheets.",
        "transport": "streamable-http",
        "endpoint": f"{MCP_BASE_URL}/excel",
        "tools": {
            "upsert_row": "excel.upsert_row",
        },
        "default_headers": {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        },
        "timeout_seconds": 8,
    },
    "Docx": {
        "name": "Docx",
        "server_key": "docx",
        "version": "1.0.0",
        "description": "Docx document generation for loan summaries and borrower packets.",
        "transport": "streamable-http",
        "endpoint": f"{MCP_BASE_URL}/docx",
        "tools": {
            "create_document": "docx.create_document",
        },
        "default_headers": {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        },
        "timeout_seconds": 8,
    },
    "Google Calendar": {
        "name": "Google Calendar",
        "server_key": "google_calendar",
        "version": "1.0.0",
        "description": "Google Calendar scheduling for underwriting and borrower meetings.",
        "transport": "streamable-http",
        "endpoint": f"{MCP_BASE_URL}/google-calendar",
        "tools": {
            "create_event": "google_calendar.create_event",
        },
        "default_headers": {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        },
        "timeout_seconds": 8,
    },
}


def _validate_endpoint(endpoint: str) -> None:
    """Ensure the endpoint belongs to the trusted MCP_BASE_URL allowlist."""
    if not endpoint.startswith(MCP_BASE_URL):
        raise ValueError(
            f"Endpoint '{endpoint}' is not trusted. Must start with '{MCP_BASE_URL}'."
        )


def _compute_hmac_signature(payload_bytes: bytes) -> str:
    """Compute an HMAC-SHA256 signature over the payload bytes using the shared secret."""
    return hmac.new(
        MCP_SHARED_SECRET.encode("utf-8"),
        payload_bytes,
        hashlib.sha256,
    ).hexdigest()


def sanitize_arguments(arguments: Any) -> dict[str, Any]:
    """Validate and sanitize the arguments dict before use in the MCP payload."""
    if not isinstance(arguments, dict):
        raise TypeError("arguments must be a dict")

    allowed_types = (str, int, float, bool, type(None))
    sanitized: dict[str, Any] = {}

    for key, value in arguments.items():
        if not isinstance(key, str) or not key:
            raise ValueError(f"Invalid argument key: {key!r}. Keys must be non-empty strings.")

        sanitized[key] = _sanitize_value(value, allowed_types)

    return sanitized


def _sanitize_value(value: Any, allowed_types: tuple) -> Any:
    """Recursively sanitize a value."""
    if isinstance(value, bool) or isinstance(value, (int, float, type(None))):
        return value
    if isinstance(value, str):
        stripped = value.strip()
        if len(stripped) > MAX_STRING_LENGTH:
            raise ValueError(
                f"String value exceeds maximum allowed length of {MAX_STRING_LENGTH} characters."
            )
        return stripped
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for k, v in value.items():
            if not isinstance(k, str) or not k:
                raise ValueError(f"Invalid nested key: {k!r}. Keys must be non-empty strings.")
            sanitized[k] = _sanitize_value(v, allowed_types)
        return sanitized
    if isinstance(value, list):
        return [_sanitize_value(item, allowed_types) for item in value]
    raise TypeError(f"Disallowed value type: {type(value).__name__}")


def _sanitize_mcp_body(body: Any) -> Any:
    """Validate and sanitize the MCP server response body."""
    if not isinstance(body, dict):
        logger.warning("MCP response body is not a dict; wrapping in raw container.")
        return {"raw": str(body)[:MAX_STRING_LENGTH]}

    raw_size = len(json.dumps(body))
    if raw_size > MAX_BODY_SIZE:
        raise ValueError(
            f"MCP response body size {raw_size} exceeds limit of {MAX_BODY_SIZE} bytes."
        )

    # Validate JSON-RPC 2.0 structure
    if "jsonrpc" in body and body.get("jsonrpc") != "2.0":
        logger.warning("MCP response has unexpected jsonrpc version: %s", body.get("jsonrpc"))

    return _sanitize_body_value(body)


def _sanitize_body_value(value: Any) -> Any:
    """Recursively sanitize values in the MCP response body."""
    if isinstance(value, bool) or isinstance(value, (int, float, type(None))):
        return value
    if isinstance(value, str):
        return value.strip()[:MAX_STRING_LENGTH]
    if isinstance(value, dict):
        return {str(k): _sanitize_body_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize_body_value(item) for item in value]
    return str(value)[:MAX_STRING_LENGTH]


async def call_mcp_server(
    agent: dict[str, Any],
    server_name: str,
    tool_alias: str,
    arguments: dict[str, Any],
) -> dict[str, Any]:
    server = MCP_SERVERS[server_name]
    tool_name = server["tools"][tool_alias]
    headers = dict(server.get("default_headers", {}))

    for header_name, header_value in agent.get("external_system_credentials", {}).get(server_name, {}).items():
        headers[header_name] = header_value

    # Validate and sanitize arguments before constructing the payload
    sanitized_args = sanitize_arguments(arguments)

    # Validate the endpoint against the trusted allowlist
    _validate_endpoint(server["endpoint"])

    payload = {
        "jsonrpc": "2.0",
        "id": str(uuid4()),
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": sanitized_args,
        },
    }

    # Compute HMAC signature over the serialized payload
    payload_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
    signature = _compute_hmac_signature(payload_bytes)
    headers["X-MCP-Signature"] = signature

    def _post() -> dict[str, Any]:
        logger.info(
            "MCP outgoing request: server=%s endpoint=%s tool=%s payload_id=%s",
            server["name"],
            server["endpoint"],
            tool_name,
            payload["id"],
        )
        try:
            response = requests.post(
                server["endpoint"],
                json=payload,
                headers=headers,
                timeout=server.get("timeout_seconds", 8),
            )
            logger.info(
                "MCP response received: server=%s tool=%s status_code=%s ok=%s",
                server["name"],
                tool_name,
                response.status_code,
                response.ok,
            )
            try:
                body = response.json()
            except ValueError:
                body = {"raw": response.text}

            # Validate the server's response signature if present
            server_signature = response.headers.get("X-MCP-Signature")
            if server_signature is not None:
                response_bytes = response.content
                expected_signature = _compute_hmac_signature(response_bytes)
                if not hmac.compare_digest(server_signature, expected_signature):
                    logger.warning(
                        "MCP server response signature mismatch for server=%s tool=%s",
                        server["name"],
                        tool_name,
                    )

            # Sanitize the response body
            sanitized_body = _sanitize_mcp_body(body)

            return {
                "server": server["name"],
                "endpoint": server["endpoint"],
                "tool": tool_name,
                "ok": response.ok,
                "status_code": response.status_code,
                "body": sanitized_body,
            }
        except requests.RequestException as exc:
            logger.error(
                "MCP request exception: server=%s endpoint=%s tool=%s error=%s",
                server["name"],
                server["endpoint"],
                tool_name,
                str(exc),
            )
            return {
                "server": server["name"],
                "endpoint": server["endpoint"],
                "tool": tool_name,
                "ok": False,
                "error": str(exc),
            }

    return await asyncio.to_thread(_post)


def format_mcp_activity(mcp_activity: list[dict[str, Any]]) -> str:
    if not mcp_activity:
        return "No MCP server was called."

    lines = []
    for item in mcp_activity:
        if item.get("ok"):
            lines.append(
                f"- {item['server']} -> {item['tool']} ({item.get('status_code', 'ok')})"
            )
        else:
            lines.append(
                f"- {item['server']} -> {item['tool']} failed ({item.get('error', item.get('status_code', 'unknown error'))})"
            )
    return "\n".join(lines)