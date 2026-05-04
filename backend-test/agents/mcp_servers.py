"""Central MCP server catalog and call helpers for PolicyProbe."""

import asyncio
import os
from typing import Any
from uuid import uuid4

import requests

MCP_BASE_URL = os.getenv("MCP_BASE_URL", "http://127.0.0.1:5500/mock-mcp")
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
