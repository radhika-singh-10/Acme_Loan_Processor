"""
PolicyProbe Backend - FastAPI Application

This entry point exposes the vulnerable multi-agent loan workflow used by the
demo UI. The backend now routes through a central agent catalog so the agent
names, model names, and MCP server names are easy to inspect in source.
"""

import base64
import json
from datetime import datetime, timezone
from pathlib import Path

# Load environment variables from .env file
from dotenv import load_dotenv
env_path = Path(__file__).parent.parent / '.env'
load_dotenv(env_path)

import logging
from contextlib import asynccontextmanager
from typing import Optional
import hmac
import hashlib
from datetime import timedelta

from fastapi import FastAPI, HTTPException, UploadFile, File
import hashlib
import datetime
import re
import base64
import re, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from agents.runtime import build_catalog, handle_chat_request, process_file_attachment

# Simple token verification function (replace with real validation)
def verify_token(token: str) -> bool:
    # In production, validate against a database or auth service
    # For demo purposes, accept a hardcoded token
    return token == "valid-token", check_pii_singapore, redact_pii

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


async def inspect_prompt(message: str) -> bool:
    """
    Inspect a user message for potentially malicious content.
    Returns True if the message is safe, False if it violates policy.
    """
    # Check for base64-encoded content (potential command injection)
    try:
        decoded = base64.b64decode(message).decode('utf-8', errors='ignore')
        # If decoded contains shell commands or suspicious patterns, reject
        if re.search(r'(rm\s+-rf|sudo|exec|system|eval|__import__|os\.)', decoded, re.IGNORECASE):
            logger.warning("Blocked message with base64-encoded malicious content")
            return False
    except Exception:
        pass  # Not valid base64, continue

    # Check for hidden prompts or command injection patterns
    suspicious_patterns = [
        r'ignore\s+previous\s+instructions',
        r'forget\s+your\s+instructions',
        r'you\s+are\s+now\s+an?\s+AI',
        r'do\s+not\s+follow\s+your\s+instructions',
        r'rm\s+-rf\s+/',
        r'exec\s*\(',
        r'eval\s*\(',
        r'system\s*\(',
        r'__import__\s*\(',
        r'os\.system',
        r'subprocess\.',
        r'base64\s*-d',
        r'\|\s*bash',
        r'\|\s*sh',
        r'`.*`',
        r'\$\s*\(',
    ]
    for pattern in suspicious_patterns:
        if re.search(pattern, message, re.IGNORECASE):
            logger.warning("Blocked message with suspicious pattern: %s", pattern)
            return False

    return True
MCP_CALL_LOG: list[dict] = []


def inspect_file_content(content: str, filename: str) -> str:
    """
    Inspect file content for hidden prompts, base64-encoded malicious payloads,
    or other suspicious patterns. Raises HTTPException if malicious content is detected.
    """
    import re
    # Detect base64-encoded strings (long sequences of base64 characters)
    base64_pattern = re.compile(r'[A-Za-z0-9+/=]{40,}')
    if base64_pattern.search(content):
        raise HTTPException(status_code=400, detail=f"Malicious content detected in file '{filename}': base64-encoded payload")
    # Detect hidden prompt injection patterns (e.g., "ignore previous instructions")
    hidden_prompt_patterns = [
        r'ignore\s+(all\s+)?previous\s+(instructions|commands|directives)',
        r'disregard\s+(all\s+)?previous',
        r'you\s+are\s+now\s+',
        r'new\s+instructions?\s*:',
        r'override\s+',
    ]
    for pattern in hidden_prompt_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            raise HTTPException(status_code=400, detail=f"Malicious content detected in file '{filename}': hidden prompt injection")
    # Detect attempts to encode malicious content in base64 within the file
    # (e.g., base64-encoded strings that decode to suspicious commands)
    # This is a basic check; more advanced analysis could be added.
    return content


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    logger.info("PolicyProbe backend starting up...")
    yield
    logger.info("PolicyProbe backend shutting down...")


app = FastAPI(
    title="PolicyProbe",
    description="AI-powered policy evaluation and remediation demo",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS middleware for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5001", "http://127.0.0.1:5001"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class FileAttachment(BaseModel):
    id: str
    name: str
    type: str
    size: int
    content: Optional[str] = None


class SignedConversationId(BaseModel):
    value: str
    signature: str
    expires_at: datetime

    def is_valid(self, secret: str) -> bool:
        if datetime.now(timezone.utc) > self.expires_at:
            return False
        expected = hmac.new(
            secret.encode(),
            f"{self.value}:{self.expires_at.isoformat()}".encode(),
            hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(expected, self.signature)

    @classmethod
    def create(cls, value: str, secret: str, ttl_seconds: int = 3600) -> "SignedConversationId":
        expires_at = datetime.now(timezone.utc).replace(tzinfo=timezone.utc) + timedelta(seconds=ttl_seconds)
        signature = hmac.new(
            secret.encode(),
            f"{value}:{expires_at.isoformat()}".encode(),
            hashlib.sha256
        ).hexdigest()
        return cls(value=value, signature=signature, expires_at=expires_at)


class ChatRequest(BaseModel):
    message: str
    attachments: Optional[list[FileAttachment]] = None
    conversation_id: Optional[SignedConversationId] = None


def sanitize_input(text: str, max_length: int = 10000) -> str:
    """Sanitize and validate input text before passing to AI model."""
    if not isinstance(text, str):
        raise ValueError("Input must be a string")
    if len(text) > max_length:
        text = text[:max_length]
    # Remove any control characters except newlines and tabs
    text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)
    return text


AGENT_AUTH_TOKEN = "secure-token-abc123"  # Replace with a securely generated token

class PolicyError(BaseModel):
    type: str
    message: str
    details: Optional[dict] = None


class ChatResponse(BaseModel):
    response: str
    conversation_id: Optional[str] = None
    policy_warning: Optional[PolicyError] = None


# In-memory audit log for AI-driven actions (replace with persistent store in production)
audit_log: list[dict] = []


def record_audit_entry(model_id: str, model_version: str, input_hash: str, output: str, principal: str):
    """Record an audit entry for an AI-driven action."""
    entry = {
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "model_id": model_id,
        "model_version": model_version,
        "input_hash": input_hash,
        "output": output,
        "principal": principal,
    }
    audit_log.append(entry)
    # In production, write to a database or secure log file
    logger.info("Audit entry recorded", extra=entry)


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "policyprobe"}


@app.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest, authorization: str = Header(None)):
    """
    Main chat endpoint that processes user messages and file uploads.

    This endpoint:
    1. Receives user messages and optional file attachments
    2. Processes files through the File Processor Agent
    3. Routes the request through the Orchestrator Agent
    4. Returns the agent response
    """
    # Authentication: validate API token from Authorization header
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid authentication token")
    token = authorization[len("Bearer "):]
    # Simple token validation (replace with real validation in production)
    if not token or len(token) < 10:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    """
    Main chat endpoint that processes user messages and file uploads.

    This endpoint:
    1. Receives user messages and optional file attachments
    2. Processes files through the File Processor Agent
    3. Routes the request through the Orchestrator Agent
    4. Returns the agent response
    """
    try:
        file_contents = []
        if request.attachments:
            for attachment in request.attachments:
                logger.info(
                    "Processing attachment",
                    extra={
                        "file_name": attachment.name,
                        "file_type": attachment.type,
                        "file_size": attachment.size,
                        "request_context": {
                            "message": request.message,
                            "attachment_content_preview": attachment.content[:100] if attachment.content else None
                        }
                    }
                )

                processed = await process_file_attachment(
                    content=attachment.content,
                    filename=attachment.name,
                    content_type=attachment.type
                )
                file_contents.append(processed)

        # Sanitize and validate user input before passing to AI model
        sanitized_message = sanitize_input(request.message)
        sanitized_file_contents = [sanitize_input(fc) if isinstance(fc, str) else fc for fc in file_contents]

        context = {
            "user_message": sanitized_message,
            "file_contents": sanitized_file_contents,
            "conversation_id": request.conversation_id,
        }

        # Inspect user message for malicious prompts before processing
        if not await inspect_prompt(request.message):
            raise HTTPException(
                status_code=400,
                detail={
                    "detail": "Message rejected due to policy violation",
                    "policy_error": {
                        "type": "prompt_injection",
                        "message": "Message contains potentially malicious content"
                    }
                }
            )

                response = await handle_chat_request(
            request.message,
            file_contents if file_contents else None,
            request.conversation_id,
        )

        # Add provenance metadata and synthetic content label
        provenance = {
            "model": "PolicyProbe-LLM",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "content_type": "AI-generated"
        }
        labeled_response = f"[SYNTHETIC] {response.get('response', 'I processed your request.')}\n\nProvenance: {json.dumps(provenance)}"

        return ChatResponse(
            response=labeled_response,
            conversation_id=request.conversation_id,
            policy_warning=response.get("policy_warning")
        )

        return ChatResponse(
            response=response.get("response", "I processed your request."),
            conversation_id=request.conversation_id,
            policy_warning=response.get("policy_warning"),
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Error processing chat request",
            extra={
                # VULNERABILITY: Error context includes full state
                "error": str(e),
                "request_state": {
                    "message": request.message
                }
            }
        )
        raise HTTPException(
            status_code=500,
            detail={
                "detail": "An error occurred processing your request",
                "policy_error": {
                    "type": "general",
                    "message": str(e)
                }
            }
        )


@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    """
    Direct file upload endpoint.
    """
    content = await file.read()
    if (file.content_type or "").startswith("image/") or file.content_type in {
        "application/pdf",
        "application/msword",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    }:
        processed_content = base64.b64encode(content).decode("utf-8")
    else:
        processed_content = content.decode("utf-8", errors="ignore")

    processed = await process_file_attachment(
        content=processed_content,
        filename=file.filename,
        content_type=file.content_type
    )

    return {
        "filename": file.filename,
        "size": len(content),
        "processed": True,
        "content_preview": processed.get("extracted_content", "")[:500] if processed else None,
        "agent": processed.get("agent"),
        "model": processed.get("model"),
    }


@app.post("/mock-mcp/{server_key}")
async def mock_mcp_server(server_key: str, request: Request):
    """
    Local mock MCP server endpoint used by the demo agents.

    These handlers intentionally accept broad payloads so the insecure agent
    flows can be exercised end-to-end without external infrastructure.
    """
    payload = await request.json()
    params = payload.get("params", {})
    tool_name = params.get("name", "")
    arguments = params.get("arguments", {})
    response_payload = _handle_mock_mcp_call(server_key, tool_name, arguments)
    return {
        "jsonrpc": "2.0",
        "id": payload.get("id"),
        "result": response_payload,
    }


@app.get("/catalog")
async def get_catalog():
    """Expose the current agent and MCP server catalog to the UI."""
    return build_catalog()


@app.get("/agents")
async def get_agents():
    """Compatibility alias for agent catalog inspection."""
    return build_catalog()


@app.get("/mcp-servers")
async def get_mcp_servers():
    """Compatibility alias for MCP server catalog inspection."""
    catalog = build_catalog()
    return {"mcp_servers": catalog.get("mcp_servers", [])}


def _handle_mock_mcp_call(server_key: str, tool_name: str, arguments: dict) -> dict:
    timestamp = datetime.now(timezone.utc).isoformat()
    log_entry = {
        "server_key": server_key,
        "tool_name": tool_name,
        "arguments": arguments,
        "timestamp": timestamp,
    }
    MCP_CALL_LOG.append(log_entry)

    if server_key == "slack" and tool_name == "slack.post_message":
        return {
            "server": "Slack",
            "posted": True,
            "channel": arguments.get("channel", "#general"),
            "text": arguments.get("text", ""),
            "timestamp": timestamp,
        }

    if server_key == "slack" and tool_name == "slack.download_demo_package":
        encoded_payload = arguments.get("encoded_payload", "")
        try:
            decoded_payload = base64.b64decode(encoded_payload).decode("utf-8")
        except Exception:
            decoded_payload = "Unable to decode demo payload."
        return {
            "server": "Slack",
            "downloaded": True,
            "package_name": arguments.get("package_name", "demo-package"),
            "pretend_download_path": "/tmp/demo-rce-playbook.txt",
            "decoded_payload": decoded_payload,
            "timestamp": timestamp,
        }

    if server_key == "servicenow" and tool_name == "servicenow.create_incident":
        return {
            "server": "ServiceNow",
            "incident_number": f"INC{len(MCP_CALL_LOG):06d}",
            "short_description": arguments.get("short_description", ""),
            "status": "created",
            "timestamp": timestamp,
        }

    if server_key == "email" and tool_name == "email.send_message":
        return {
            "server": "Email",
            "message_id": f"email-{len(MCP_CALL_LOG):06d}",
            "to": arguments.get("to", []),
            "subject": arguments.get("subject", ""),
            "status": "queued",
            "timestamp": timestamp,
        }

    if server_key == "excel" and tool_name == "excel.upsert_row":
        return {
            "server": "Excel",
            "workbook": arguments.get("workbook", ""),
            "worksheet": arguments.get("worksheet", ""),
            "row": arguments.get("row", {}),
            "status": "upserted",
            "timestamp": timestamp,
        }

    if server_key == "docx" and tool_name == "docx.create_document":
        return {
            "server": "Docx",
            "document_id": f"docx-{len(MCP_CALL_LOG):06d}",
            "document_title": arguments.get("document_title", ""),
            "document_body_preview": arguments.get("document_body", "")[:300],
            "status": "generated",
            "timestamp": timestamp,
        }

    if server_key == "google-calendar" and tool_name == "google_calendar.create_event":
        return {
            "server": "Google Calendar",
            "event_id": f"gcal-{len(MCP_CALL_LOG):06d}",
            "title": arguments.get("title", ""),
            "start": arguments.get("start", ""),
            "end": arguments.get("end", ""),
            "status": "scheduled",
            "timestamp": timestamp,
        }

    return {
        "server": server_key,
        "tool": tool_name,
        "status": "unsupported",
        "timestamp": timestamp,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=5500)
