"""Central MCP server catalog and call helpers for Acme Loan Processor."""
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


import asyncio
import os
from typing import Any
from uuid import uuid4

import requests

MCP_BASE_URL = os.getenv("MCP_BASE_URL", "http://127.0.0.1:5500/mock-mcp")


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
            # LINEAJE: enforce() `response` at api->agent post_tool — scan flagged AI_IAC_015 (Enforce URL allowlists for agent fetches, tools, and outbound HTTP.); AI_IAC_018 (Enforce cryptographically verified user-to-agent binding for every request.); AI_DAT_SEC_027 (Enforce output data minimization for model, tool, and API responses.). Mask/block; do not remove without review. site_id='site:sha256:f87bf0b02e4dd7d487508bbc4ab603ccde64d095b0be2edce2464a63d343bbad'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:f87bf0b02e4dd7d487508bbc4ab603ccde64d095b0be2edce2464a63d343bbad', phase='post_tool', boundary={'source': 'external_endpoint', 'sink': 'agent_message'}, candidate_policies=[], fail_mode='ALLOW_WITH_AUDIT', source_type='api', destination_type='agent')
            response = _gr_client.enforce(_gr_site, response, content_type='application/json', variable_name='response', source_file=__file__, before_line=139)
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
