"""
Agent Authentication Module

Provides authentication and authorization for inter-agent communication.

SECURITY NOTES:
- Authentication is enforced for all inter-agent communication
- Tokens are generated and validated for every request
- All agent identities must be verified before processing requests
"""

from .agent_auth import AgentAuthenticator, AgentIdentity, AuthResult

__all__ = ["AgentAuthenticator", "AgentIdentity", "AuthResult"]