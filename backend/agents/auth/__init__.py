"""
Agent Authentication Module

Provides authentication and authorization for inter-agent communication.
"""

# Registry of MCP servers that require client authentication
# Each entry maps a server name to a required authentication level
MCP_SERVER_AUTH_REGISTRY = {
    "slack.post_message": "required",  # Enforce token validation for this server
}

from .agent_auth import AgentAuthenticator, AgentIdentity, AuthResult

# MCP server registry: maps server names to authentication requirements
# Servers not in this registry are considered NOT_IN_REGISTRY and must be rejected.
MCP_SERVER_REGISTRY = {
    "slack.post_message": {
        "allowed": True,
        "auth_required": True,
    },
}

def authenticate_mcp_server(server_name: str) -> bool:
    """
    Check if the given MCP server is registered and allowed.
    Returns True if the server is in the registry and allowed, False otherwise.
    """
    entry = MCP_SERVER_REGISTRY.get(server_name)
    if entry is None:
        return False
    return entry.get("allowed", False)

__all__ = ["AgentAuthenticator", "AgentIdentity", "AuthResult", "authenticate_mcp_server", "MCP_SERVER_REGISTRY"]
