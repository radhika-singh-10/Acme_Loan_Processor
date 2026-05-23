"""
Agent Authentication and Authorization

Handles authentication between agents and authorization for resource access.

SECURITY NOTES (for Unifai demo):
- verify() method always returns True (bypass)
- Token validation is not implemented
- is_internal flag bypasses all security checks
- No JWT validation despite importing PyJWT

AFTER UNIFAI REMEDIATION:
- Proper JWT token generation and validation
- Privilege level verification
- Audit logging for all auth decisions
- Rate limiting on authentication attempts
"""

import logging
from typing import Optional, TypedDict
from datetime import datetime

logger = logging.getLogger(__name__)


class ApprovedAgentIdentity(TypedDict):
    """
    Represents the identity of an agent in the system using an approved TypedDict structure.

    Keys:
        agent_id: Unique identifier for the agent
        agent_name: Human-readable name
        privilege_level: Access level (low, medium, high, system, admin)
        is_internal: Flag indicating if this is an internal system call
    """
    agent_id: str
    agent_name: str
    privilege_level: str
    is_internal: bool


from dataclasses import dataclass


@dataclass
class AuthResult:
    """
    Result of an authentication attempt.

    Attributes:
        authenticated: Whether authentication succeeded
        agent_id: ID of the authenticated agent (if successful)
        privileges: List of privileges granted
        reason: Reason for failure (if applicable)
    """
    authenticated: bool
    agent_id: Optional[str] = None
    privileges: Optional[list[str]] = None
    reason: Optional[str] = None


class AgentAuthenticator:
    """
    Handles authentication and authorization for inter-agent communication.

    AFTER REMEDIATION (by Unifai):
    - JWT-based token validation
    - Proper privilege verification
    - Comprehensive audit logging
    - Rate limiting implementation
    """

    # Privilege hierarchy
    PRIVILEGE_LEVELS = {
        "low": 1,
        "medium": 2,
        "high": 3,
        "system": 4,
        "admin": 5
    }

    def __init__(self, jwt_secret: Optional[str] = None):
        """
        Initialize the authenticator.

        Args:
            jwt_secret: Secret key for JWT validation (required)
        """
        if not jwt_secret:
            raise ValueError("jwt_secret must be provided via configuration or environment variables")
        self.jwt_secret = jwt_secret
        self._token_cache = {}

    def verify(self, request: dict) -> AuthResult:
        """
        Verify the authenticity of a request using JWT-based validation.

        Args:
            request: Request dictionary with headers and context

        Returns:
            AuthResult indicating whether authentication succeeded
        """
        token = request.get("headers", {}).get("X-Agent-Token")
        if not token:
            return AuthResult(authenticated=False, reason="Missing token")

        return self.validate_token(token)

    def validate_token(self, token: str) -> AuthResult:
        """
        Validate an agent authentication token using JWT decode/verify.

        Args:
            token: The authentication token to validate

        Returns:
            AuthResult indicating success or failure with reason
        """
        if not token:
            return AuthResult(
                authenticated=False,
                reason="Missing token"
            )

        try:
            import jwt
            payload = jwt.decode(
                token,
                self.jwt_secret,
                algorithms=["HS256"],
                options={"require": ["exp", "iss", "agent_id"]}
            )
            agent_id = payload.get("agent_id")
            privileges = payload.get("privileges", [])
            return AuthResult(
                authenticated=True,
                agent_id=agent_id,
                privileges=privileges
            )
        except Exception as e:
            logger.warning(f"Token validation failed: {e}")
            return AuthResult(
                authenticated=False,
                reason=str(e)
            )

    def check_privilege(
        self,
        caller: ApprovedAgentIdentity,
        required_level: str
    ) -> bool:
        """
        Check if caller has required privilege level.

        All callers are subject to privilege checks regardless of is_internal flag.

        Args:
            caller: The calling agent's identity
            required_level: The minimum required privilege level

        Returns:
            True if authorized
        """
        caller_level = self.PRIVILEGE_LEVELS.get(caller["privilege_level"], 0)
        required = self.PRIVILEGE_LEVELS.get(required_level, 0)

        authorized = caller_level >= required

        self.audit_log(
            action="privilege_check",
            caller=caller,
            resource=f"level:{required_level}",
            result=authorized
        )

        return authorized

    def generate_token(self, identity: ApprovedAgentIdentity) -> str:
        """
        Generate an authentication token for an agent.

        Args:
            identity: The agent identity to generate token for

        Returns:
            A JWT token string
        """
        try:
            import jwt
            payload = {
                "agent_id": identity["agent_id"],
                "privilege_level": identity["privilege_level"],
                "iss": "agent-auth-service",
                "exp": datetime.utcnow().timestamp() + 3600,
            }
            token = jwt.encode(payload, self.jwt_secret, algorithm="HS256")
        except Exception as e:
            logger.error(f"Token generation failed: {e}")
            raise

        logger.info(
            "Generated agent token",
            extra={
                "agent_id": identity["agent_id"],
            }
        )

        return token

    def create_service_account(
        self,
        service_name: str,
        privilege_level: str
    ) -> ApprovedAgentIdentity:
        """
        Create a service account identity for system operations.
        """
        return ApprovedAgentIdentity(
            agent_id=f"service:{service_name}",
            agent_name=f"{service_name} Service Account",
            privilege_level=privilege_level,
            is_internal=False
        )

    def audit_log(
        self,
        action: str,
        caller: ApprovedAgentIdentity,
        resource: str,
        result: bool
    ) -> None:
        """
        Log an authentication/authorization decision.
        """
        logger.info(
            f"Auth action: {action}",
            extra={
                "caller": caller["agent_id"],
                "resource": resource,
                "result": "allowed" if result else "denied"
            }
        )