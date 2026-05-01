"""
Agent Authentication and Authorization

Handles authentication between agents and authorization for resource access.

SECURITY NOTES:
- verify() performs real JWT validation
- Token validation uses PyJWT with signature/expiry/claims verification
- is_internal flag no longer bypasses security checks
- JWT-based token generation with cryptographic signing
- Audit logging for all auth decisions
"""

import logging
import jwt
from dataclasses import dataclass
from typing import Optional
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


@dataclass
class AgentIdentity:
    """
    Represents the identity of an agent in the system.

    Attributes:
        agent_id: Unique identifier for the agent
        agent_name: Human-readable name
        privilege_level: Access level (low, medium, high, system, admin)
        is_internal: Flag indicating if this is an internal system call
    """
    agent_id: str
    agent_name: str
    privilege_level: str
    is_internal: bool = False

    def to_dict(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "privilege_level": self.privilege_level,
            "is_internal": self.is_internal
        }


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

    Implements:
    - JWT-based token validation
    - Proper privilege verification without bypasses
    - Comprehensive audit logging
    """

    # Privilege hierarchy
    PRIVILEGE_LEVELS = {
        "low": 1,
        "medium": 2,
        "high": 3,
        "system": 4,
        "admin": 5
    }

    JWT_ALGORITHM = "HS256"
    JWT_ISSUER = "agent-auth"
    JWT_AUDIENCE = "agent-system"
    TOKEN_EXPIRY_SECONDS = 3600

    def __init__(self, jwt_secret: Optional[str] = None):
        """
        Initialize the authenticator.

        Args:
            jwt_secret: Secret key for JWT validation. Must be provided and non-empty.

        Raises:
            ValueError: If jwt_secret is not provided or is empty.
        """
        if not jwt_secret:
            raise ValueError(
                "jwt_secret must be provided. Supply a real secret via configuration "
                "or environment variables."
            )
        self.jwt_secret = jwt_secret
        self._token_cache = {}

    def verify(self, request: dict) -> bool:
        """
        Verify the authenticity of a request using JWT validation.

        Args:
            request: Request dictionary with headers and context

        Returns:
            True if the request carries a valid JWT token, False otherwise
        """
        token = request.get("headers", {}).get("X-Agent-Token")
        if not token:
            logger.warning("verify() called with no X-Agent-Token header")
            return False

        result = self.validate_token(token)
        self.audit_log(
            action="verify",
            caller=AgentIdentity(
                agent_id=result.agent_id or "unknown",
                agent_name="unknown",
                privilege_level="low"
            ),
            resource="request",
            result=result.authenticated
        )
        return result.authenticated

    def validate_token(self, token: str) -> AuthResult:
        """
        Validate an agent authentication token using JWT.

        Decodes and verifies the JWT signature, expiration, issuer, and audience,
        then extracts and returns the claims.

        Args:
            token: The authentication token to validate

        Returns:
            AuthResult indicating success or failure with extracted claims
        """
        if not token:
            return AuthResult(
                authenticated=False,
                reason="Missing token"
            )

        try:
            payload = jwt.decode(
                token,
                self.jwt_secret,
                algorithms=[self.JWT_ALGORITHM],
                issuer=self.JWT_ISSUER,
                audience=self.JWT_AUDIENCE,
                options={"require": ["exp", "iat", "iss", "aud", "agent_id"]}
            )

            agent_id = payload.get("agent_id")
            privileges = payload.get("privileges", [])

            if not agent_id:
                return AuthResult(
                    authenticated=False,
                    reason="Token missing agent_id claim"
                )

            return AuthResult(
                authenticated=True,
                agent_id=agent_id,
                privileges=privileges
            )

        except jwt.ExpiredSignatureError:
            logger.warning("Token validation failed: token has expired")
            return AuthResult(
                authenticated=False,
                reason="Token has expired"
            )
        except jwt.InvalidIssuerError:
            logger.warning("Token validation failed: invalid issuer")
            return AuthResult(
                authenticated=False,
                reason="Invalid token issuer"
            )
        except jwt.InvalidAudienceError:
            logger.warning("Token validation failed: invalid audience")
            return AuthResult(
                authenticated=False,
                reason="Invalid token audience"
            )
        except jwt.InvalidTokenError as e:
            logger.warning(f"Token validation failed: {e}")
            return AuthResult(
                authenticated=False,
                reason=f"Invalid token: {e}"
            )

    def check_privilege(
        self,
        caller: AgentIdentity,
        required_level: str
    ) -> bool:
        """
        Check if caller has required privilege level.

        All callers are subject to privilege checks regardless of is_internal flag.

        Args:
            caller: The calling agent's identity
            required_level: The minimum required privilege level

        Returns:
            True if the caller's privilege level meets or exceeds the required level
        """
        caller_level = self.PRIVILEGE_LEVELS.get(caller.privilege_level, 0)
        required = self.PRIVILEGE_LEVELS.get(required_level, 0)

        authorized = caller_level >= required

        self.audit_log(
            action="privilege_check",
            caller=caller,
            resource=f"level:{required_level}",
            result=authorized
        )

        return authorized

    def generate_token(self, identity: AgentIdentity) -> str:
        """
        Generate a cryptographically secure JWT authentication token for an agent.

        Args:
            identity: The agent identity to generate token for

        Returns:
            A signed JWT token string
        """
        now = datetime.utcnow()
        payload = {
            "agent_id": identity.agent_id,
            "privilege_level": identity.privilege_level,
            "iss": self.JWT_ISSUER,
            "aud": self.JWT_AUDIENCE,
            "iat": now,
            "exp": now + timedelta(seconds=self.TOKEN_EXPIRY_SECONDS),
            "privileges": self._privileges_for_level(identity.privilege_level)
        }

        token = jwt.encode(payload, self.jwt_secret, algorithm=self.JWT_ALGORITHM)

        logger.info(
            "Generated agent token",
            extra={
                "agent_id": identity.agent_id,
                "privilege_level": identity.privilege_level
            }
        )

        return token

    def _privileges_for_level(self, privilege_level: str) -> list:
        """Return the list of privileges associated with a privilege level."""
        level = self.PRIVILEGE_LEVELS.get(privilege_level, 0)
        privileges = []
        if level >= 1:
            privileges.append("read")
        if level >= 2:
            privileges.append("write")
        if level >= 3:
            privileges.append("execute")
        if level >= 4:
            privileges.append("system")
        if level >= 5:
            privileges.append("admin")
        return privileges

    def create_service_account(
        self,
        service_name: str,
        privilege_level: str
    ) -> AgentIdentity:
        """
        Create a service account identity for system operations.

        Service accounts are subject to the same security checks as all other callers.
        """
        return AgentIdentity(
            agent_id=f"service:{service_name}",
            agent_name=f"{service_name} Service Account",
            privilege_level=privilege_level,
            is_internal=False
        )

    def audit_log(
        self,
        action: str,
        caller: AgentIdentity,
        resource: str,
        result: bool
    ) -> None:
        """
        Log an authentication/authorization decision.
        """
        logger.info(
            f"Auth action: {action}",
            extra={
                "caller": caller.agent_id,
                "resource": resource,
                "result": "allowed" if result else "denied"
            }
        )