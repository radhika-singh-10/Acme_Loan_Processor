"""Central MCP server catalog and call helpers for PolicyProbe."""

import asyncio
import logging
import os
from typing import Any
from uuid import uuid4

import requests
import html

logger = logging.getLogger(__name__)

MCP_BASE_URL = os.getenv("MCP_BASE_URL", "https://127.0.0.1:5500/mock-mcp")


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
            "X-API-Key": os.getenv("MCP_API_KEY", "default-mcp-key"),
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
            "X-API-Key": os.getenv("MCP_API_KEY", "default-mcp-key"),
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
            "X-API-Key": os.getenv("MCP_API_KEY", "default-mcp-key"),
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
            "X-API-Key": os.getenv("MCP_API_KEY", "default-mcp-key"),
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


_audit_log: list[dict[str, Any]] = []


async def call_mcp_server(
    agent: dict[str, Any],
    server_name: str,
    tool_alias: str,
    arguments: dict[str, Any],
) -> dict[str, Any]:
    server = MCP_SERVERS[server_name]
    allowed_tools = agent.get("allowed_tools", [])
    if tool_alias not in allowed_tools:
        raise PermissionError(f"Tool '{tool_alias}' is not in the allowed tools list for this agent.")
    tool_name = server["tools"][tool_alias]
    headers = dict(server.get("default_headers", {}))

    if server_name in {"Slack", "ServiceNow", "Email"}:
            for header_name, header_value in agent.get("external_system_credentials", {}).get(server_name, {}).items():
                headers[header_name] = header_value

    # Validate and sanitize arguments
    if not isinstance(arguments, dict):
        raise ValueError("arguments must be a dictionary")
    sanitized_arguments = {}
    for key, value in arguments.items():
        if not isinstance(key, str):
            continue
        if isinstance(value, str):
            sanitized_arguments[key] = value.strip()
        else:
            sanitized_arguments[key] = value

    payload = {
        "jsonrpc": "2.0",
        "id": str(uuid4()),
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": sanitized_arguments,
        },
    }

    def _post() -> dict[str, Any]:
        try:
            response = requests.post(
                server["endpoint"],
                json=payload,
                headers=headers,
                timeout=server.get("timeout_seconds", 8),
            )
            try:
                body = response.json()
            except ValueError:
                body = {"raw": response.text}

            return {
                "server": server["name"],
                "endpoint": server["endpoint"],
                "tool": tool_name,
                "ok": response.ok,
                "status_code": response.status_code,
                "body": body,
            }
        except requests.RequestException as exc:
            return {
                "server": server["name"],
                "endpoint": server["endpoint"],
                "tool": tool_name,
                "ok": False,
                "error": str(exc),
            }

    result = await asyncio.to_thread(_post)

    # Audit logging
    import hashlib, datetime
    input_hash = hashlib.sha256(str(arguments).encode()).hexdigest()
    output_hash = hashlib.sha256(str(result.get("body", {})).encode()).hexdigest()
    _audit_log.append({
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "model_id": agent.get("model", "unknown"),
        "principal": agent.get("id", "unknown"),
        "server": server_name,
        "tool": tool_alias,
        "input_hash": input_hash,
        "output_hash": output_hash,
        "ok": result.get("ok", False),
    })

    return result


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
    formatted = "\n".join(lines)
    logger.info("MCP activity summary:\n%s", formatted)
    return formatted
