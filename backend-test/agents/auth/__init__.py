"""
Agent Authentication Module

Provides authentication and authorization for inter-agent communication.

SECURITY NOTES:
- Authentication is enforced for all inter-agent communication
- Tokens are generated and validated on every request
- All agent identities are verified before processing
"""

from .agent_auth import AgentAuthenticator, AgentIdentity, AuthResult

__all__ = ["AgentAuthenticator", "AgentIdentity", "AuthResult"]