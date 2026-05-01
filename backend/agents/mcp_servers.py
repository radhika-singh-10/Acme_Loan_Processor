"""Central MCP server catalog and call helpers for PolicyProbe."""

import asyncio
import logging
import os
import re
import unicodedata
from typing import Any
from uuid import uuid4

import requests

logger = logging.getLogger(__name__)

MCP_BASE_URL = os.getenv("MCP_BASE_URL", "https://127.0.0.1:5500/mock-mcp")

MCP_SERVER_CA_BUNDLE = os.getenv("MCP_SERVER_CA_BUNDLE", "")
MCP_SERVER_TOKEN = os.getenv("MCP_SERVER_TOKEN", "")

_AUTH_HEADER = (
    {"Authorization": f"Bearer {MCP_SERVER_TOKEN}"} if MCP_SERVER_TOKEN else {}
)

_TLS_VERIFY: Any = MCP_SERVER_CA_BUNDLE if MCP_SERVER_CA_BUNDLE else True

_MAX_VALUE_SIZE = 65536
_MAX_KEY_LENGTH = 256
_MAX_RESPONSE_SIZE = 1048576
_MAX_STRING_LENGTH = 65536
_MAX_DEPTH = 10
_MAX_KEYS = 256


def _sanitize_arguments(arguments: Any, _depth: int = 0) -> dict[str, Any]:
    if not isinstance(arguments, dict):
        raise ValueError("MCP arguments must be a dictionary.")
    if _depth > _MAX_DEPTH:
        raise ValueError("MCP arguments exceed maximum nesting depth.")
    sanitized: dict[str, Any] = {}
    for key, value in arguments.items():
        if not isinstance(key, str) or not key:
            raise ValueError(f"MCP argument key must be a non-empty string, got: {key!r}")
        if len(key) > _MAX_KEY_LENGTH:
            raise ValueError(
                f"MCP argument key exceeds maximum length of {_MAX_KEY_LENGTH}: {key!r}"
            )
        if isinstance(value, dict):
            value = _sanitize_arguments(value, _depth=_depth + 1)
        elif isinstance(value, str):
            value = value.strip()
            if len(value) > _MAX_VALUE_SIZE:
                raise ValueError(
                    f"MCP argument value for key '{key}' exceeds maximum size of {_MAX_VALUE_SIZE}."
                )
        else:
            str_repr = str(value)
            if len(str_repr) > _MAX_VALUE_SIZE:
                raise ValueError(
                    f"MCP argument value for key '{key}' exceeds maximum size of {_MAX_VALUE_SIZE}."
                )
        sanitized[key] = value
    return sanitized


def _sanitize_string_value(value: str) -> str:
    sanitized = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", value)
    if len(sanitized) > _MAX_STRING_LENGTH:
        sanitized = sanitized[:_MAX_STRING_LENGTH]
    return sanitized


def _sanitize_mcp_body(body: Any, _depth: int = 0, _key_count: list[int] | None = None) -> Any:
    if _key_count is None:
        _key_count = [0]

    if not isinstance(body, (dict, list)):
        raise ValueError(
            f"MCP response body must be a dict or list, got: {type(body).__name__}"
        )

    def _sanitize_value(value: Any, depth: int) -> Any:
        if depth > _MAX_DEPTH:
            raise ValueError("MCP response body exceeds maximum nesting depth.")
        if isinstance(value, str):
            return _sanitize_string_value(value)
        elif isinstance(value, dict):
            if _key_count[0] + len(value) > _MAX_KEYS:
                raise ValueError("MCP response body exceeds maximum key count.")
            _key_count[0] += len(value)
            return {k: _sanitize_value(v, depth + 1) for k, v in value.items()}
        elif isinstance(value, list):
            return [_sanitize_value(item, depth + 1) for item in value]
        else:
            return value

    return _sanitize_value(body, _depth)


_DEFAULT_HEADERS_BASE = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
    **_AUTH_HEADER,
}

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
            **_DEFAULT_HEADERS_BASE,
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
            **_DEFAULT_HEADERS_BASE,
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
            **_DEFAULT_HEADERS_BASE,
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
            **_DEFAULT_HEADERS_BASE,
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
            **_DEFAULT_HEADERS_BASE,
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
            **_DEFAULT_HEADERS_BASE,
        },
        "timeout_seconds": 8,
    },
}


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

    _auth_headers = {"Authorization", "X-API-Key", "X-Client-Certificate"}
    if not any(h in headers for h in _auth_headers):
        raise ValueError(
            f"No authentication credentials found for MCP server '{server_name}'. "
            "At least one of Authorization, X-API-Key, or X-Client-Certificate must be present."
        )

    arguments = _sanitize_arguments(arguments)

    payload = {
        "jsonrpc": "2.0",
        "id": str(uuid4()),
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": arguments,
        },
    }

    def _post() -> dict[str, Any]:
        logger.info(
            "MCP outgoing request: server=%s tool=%s arguments=%s",
            server["name"],
            tool_name,
            arguments,
        )
        try:
            response = requests.post(
                server["endpoint"],
                json=payload,
                headers=headers,
                timeout=server.get("timeout_seconds", 8),
                verify=_TLS_VERIFY,
            )
            try:
                raw_body = response.json()
            except ValueError:
                raw_body = {"raw": response.text}

            raw_size = len(str(raw_body))
            if raw_size > _MAX_RESPONSE_SIZE:
                raise ValueError(
                    f"MCP response body size {raw_size} exceeds maximum allowed size {_MAX_RESPONSE_SIZE}."
                )

            try:
                body = _sanitize_mcp_body(raw_body)
            except ValueError as san_exc:
                logger.warning(
                    "MCP response sanitization failed for server=%s tool=%s: %s",
                    server["name"],
                    tool_name,
                    san_exc,
                )
                body = {"error": f"Response sanitization failed: {san_exc}"}

            logger.info(
                "MCP response received: server=%s tool=%s status_code=%s ok=%s body=%s",
                server["name"],
                tool_name,
                response.status_code,
                response.ok,
                body,
            )

            return {
                "server": server["name"],
                "endpoint": server["endpoint"],
                "tool": tool_name,
                "ok": response.ok,
                "status_code": response.status_code,
                "body": body,
            }
        except requests.RequestException as exc:
            logger.error(
                "MCP request failed: server=%s tool=%s error=%s",
                server["name"],
                tool_name,
                exc,
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