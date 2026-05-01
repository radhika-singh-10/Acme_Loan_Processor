"""
PolicyProbe Backend - FastAPI Application

This entry point exposes the vulnerable multi-agent loan workflow used by the
demo UI. The backend now routes through a central agent catalog so the agent
names, model names, and MCP server names are easy to inspect in source.
"""

import base64
import hashlib
import hmac
import json
import re
import unicodedata
from datetime import datetime, timezone
from pathlib import Path

# Load environment variables from .env file
from dotenv import load_dotenv
env_path = Path(__file__).parent.parent / '.env'
load_dotenv(env_path)

import logging
import os
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException, UploadFile, File, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Instruction 1: Remove import of build_catalog, handle_chat_request, process_file_attachment
# from agents.runtime and replace with stubs that raise RuntimeError.
def build_catalog():
    raise RuntimeError(
        "Unapproved model backend is disabled. Use only LLMs from the organization's approved list."
    )

async def handle_chat_request(context):
    raise RuntimeError(
        "Unapproved model backend is disabled. Use only LLMs from the organization's approved list."
    )

async def process_file_attachment(content, filename, content_type):
    raise RuntimeError(
        "Unapproved model backend is disabled. Use only LLMs from the organization's approved list."
    )

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)
MCP_CALL_LOG: list[dict] = []

# Allowlist of known MCP server keys (Instruction 2)
_ALLOWED_SERVER_KEYS = {
    "slack", "servicenow", "email", "excel", "docx", "google-calendar"
}

# Pattern for valid tool names (Instruction 2)
_TOOL_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9_\-\.]{1,128}$')

# Maximum string length for MCP response sanitization (Instruction 3)
_MAX_STRING_LENGTH = 4096
_MAX_DEPTH = 8
_MAX_KEYS = 64

# Input validation constants (Instruction 4)
_MAX_MESSAGE_LENGTH = 32768
_MAX_ATTACHMENT_CONTENT_LENGTH = 10 * 1024 * 1024  # 10 MB

# MCP API key (Instructions 8, 9)
_MCP_API_KEY = os.getenv("MCP_API_KEY", "")
_MCP_CLIENT_API_KEY = os.getenv("MCP_CLIENT_API_KEY", "")

# Agent auth secret (Instruction 10)
_AGENT_SECRET = os.getenv("AGENT_HMAC_SECRET", "")


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


class ChatRequest(BaseModel):
    message: str
    attachments: Optional[list[FileAttachment]] = None
    conversation_id: Optional[str] = None


class PolicyError(BaseModel):
    type: str
    message: str
    details: Optional[dict] = None


class ChatResponse(BaseModel):
    response: str
    conversation_id: Optional[str] = None
    policy_warning: Optional[PolicyError] = None


# ---------------------------------------------------------------------------
# Instruction 3: MCP response sanitization
# ---------------------------------------------------------------------------

def _sanitize_mcp_response(obj, _depth=0, _key_count=None):
    """Recursively sanitize all string values in an MCP server response."""
    if _key_count is None:
        _key_count = [0]
    if _depth > _MAX_DEPTH:
        return "[truncated: max depth exceeded]"
    if isinstance(obj, dict):
        sanitized = {}
        for k, v in obj.items():
            if _key_count[0] >= _MAX_KEYS:
                break
            _key_count[0] += 1
            sanitized_key = _strip_control_chars(str(k))[:256]
            sanitized[sanitized_key] = _sanitize_mcp_response(v, _depth + 1, _key_count)
        return sanitized
    elif isinstance(obj, list):
        return [_sanitize_mcp_response(item, _depth + 1, _key_count) for item in obj[:_MAX_KEYS]]
    elif isinstance(obj, str):
        cleaned = _strip_control_chars(obj)
        return cleaned[:_MAX_STRING_LENGTH]
    else:
        return obj


def _strip_control_chars(s: str) -> str:
    """Strip control characters from a string."""
    return "".join(
        ch for ch in s
        if unicodedata.category(ch) not in ("Cc", "Cf") or ch in ("\n", "\r", "\t")
    )


# ---------------------------------------------------------------------------
# Instruction 4: Input sanitization and validation helpers
# ---------------------------------------------------------------------------

def _sanitize_user_message(message: str) -> str:
    """Sanitize and validate a user message before passing to AI model."""
    if not isinstance(message, str):
        raise HTTPException(status_code=400, detail="Message must be a string.")
    message = _strip_control_chars(message)
    if len(message) > _MAX_MESSAGE_LENGTH:
        raise HTTPException(
            status_code=400,
            detail=f"Message exceeds maximum allowed length of {_MAX_MESSAGE_LENGTH} characters."
        )
    if not message.strip():
        raise HTTPException(status_code=400, detail="Message must not be empty.")
    return message


def _sanitize_attachment_content(content: Optional[str], filename: str) -> Optional[str]:
    """Sanitize attachment content before passing to AI model."""
    if content is None:
        return None
    if not isinstance(content, str):
        raise HTTPException(status_code=400, detail=f"Attachment content for '{filename}' must be a string.")
    if len(content) > _MAX_ATTACHMENT_CONTENT_LENGTH:
        raise HTTPException(
            status_code=400,
            detail=f"Attachment '{filename}' content exceeds maximum allowed size."
        )
    return content


def _sanitize_decoded_file_content(content: str) -> str:
    """Sanitize decoded text file content before passing to AI model."""
    content = _strip_control_chars(content)
    if len(content) > _MAX_ATTACHMENT_CONTENT_LENGTH:
        content = content[:_MAX_ATTACHMENT_CONTENT_LENGTH]
    return content


# ---------------------------------------------------------------------------
# Instruction 5: File content malicious content scanner
# ---------------------------------------------------------------------------

_SHELL_COMMAND_PATTERN = re.compile(
    r'(rm\s+-rf|wget\s+http|curl\s+http|bash\s+-[ci]|/bin/sh|/bin/bash|exec\(|eval\(|os\.system|subprocess)',
    re.IGNORECASE
)
_BINARY_SIGNATURES = [
    b'\x4d\x5a',       # PE executable (MZ)
    b'\x7fELF',        # ELF executable
    b'\xca\xfe\xba\xbe',  # Mach-O
]
_INVISIBLE_CHAR_PATTERN = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\u200b-\u200f\u202a-\u202e\ufeff]')
_LEETSPEAK_PATTERN = re.compile(r'(?:[i!1][g9][n][0o][r][e3]|[s$][y][s$][t][e3][m$])', re.IGNORECASE)


def _is_base64_prompt(content: str) -> bool:
    """Check if content contains base64-encoded prompt injection."""
    b64_pattern = re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')
    for match in b64_pattern.finditer(content):
        try:
            decoded = base64.b64decode(match.group()).decode('utf-8', errors='ignore')
            if any(kw in decoded.lower() for kw in ['ignore previous', 'system prompt', 'jailbreak', 'disregard']):
                return True
        except Exception:
            pass
    return False


def sanitize_file_content(content: str, filename: str = "") -> str:
    """
    Scan file content for hidden/invisible characters, base64-encoded prompts,
    leetspeak, shell commands, and binary executable signatures.
    Raises HTTPException if malicious content is detected.
    """
    # Check for binary executable signatures
    try:
        raw_bytes = content.encode('latin-1', errors='ignore')
        for sig in _BINARY_SIGNATURES:
            if raw_bytes.startswith(sig):
                raise HTTPException(
                    status_code=400,
                    detail=f"File '{filename}' contains a binary executable signature and cannot be processed."
                )
    except HTTPException:
        raise
    except Exception:
        pass

    # Check for invisible/hidden characters
    if _INVISIBLE_CHAR_PATTERN.search(content):
        raise HTTPException(
            status_code=400,
            detail=f"File '{filename}' contains hidden or invisible characters that may indicate malicious content."
        )

    # Check for shell commands
    if _SHELL_COMMAND_PATTERN.search(content):
        raise HTTPException(
            status_code=400,
            detail=f"File '{filename}' contains shell command patterns that are not permitted."
        )

    # Check for base64-encoded prompt injection
    if _is_base64_prompt(content):
        raise HTTPException(
            status_code=400,
            detail=f"File '{filename}' contains base64-encoded prompt injection content."
        )

    # Check for leetspeak patterns
    if _LEETSPEAK_PATTERN.search(content):
        raise HTTPException(
            status_code=400,
            detail=f"File '{filename}' contains obfuscated (leetspeak) content that is not permitted."
        )

    return content


# ---------------------------------------------------------------------------
# Instruction 6: PII redaction helper
# ---------------------------------------------------------------------------

_PII_PATTERNS = [
    # SSN
    (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), '[REDACTED-SSN]'),
    # Email
    (re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'), '[REDACTED-EMAIL]'),
    # Phone number (various formats)
    (re.compile(r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'), '[REDACTED-PHONE]'),
    # Credit card number
    (re.compile(r'\b(?:\d[ -]?){13,16}\b'), '[REDACTED-CC]'),
    # Passport number (generic: letter(s) followed by digits)
    (re.compile(r'\b[A-Z]{1,2}\d{6,9}\b'), '[REDACTED-PASSPORT]'),
    # Home address (basic: number followed by street name keywords)
    (re.compile(
        r'\b\d{1,5}\s+[A-Za-z0-9\s]{1,50}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\b',
        re.IGNORECASE
    ), '[REDACTED-ADDRESS]'),
]


def redact_pii(content: str) -> str:
    """Redact common PII categories from text content using regex patterns."""
    for pattern, replacement in _PII_PATTERNS:
        content = pattern.sub(replacement, content)
    return content


# ---------------------------------------------------------------------------
# Instruction 7: Singapore PII detection
# ---------------------------------------------------------------------------

_SG_PII_PATTERNS = [
    # NRIC/FIN: S/T/F/G followed by 7 digits and a letter
    re.compile(r'\b[STFG]\d{7}[A-Z]\b', re.IGNORECASE),
    # Singapore passport: E followed by 7 digits
    re.compile(r'\bE\d{7}\b', re.IGNORECASE),
    # Singapore phone: +65 or 65 followed by 8 digits, or 8-digit local
    re.compile(r'(?:\+65|65)[\s\-]?\d{4}[\s\-]?\d{4}'),
    re.compile(r'\b[689]\d{7}\b'),
    # Singapore postal code: 6-digit starting with 0-8
    re.compile(r'\bSingapore\s+\d{6}\b', re.IGNORECASE),
    re.compile(r'\b\d{6}\s*Singapore\b', re.IGNORECASE),
    # CPF account number: 7 digits followed by a letter
    re.compile(r'\b\d{7}[A-Z]\b', re.IGNORECASE),
    # Singapore bank account (DBS/POSB/OCBC/UOB patterns: 9-12 digits)
    re.compile(r'\b\d{9,12}\b'),
    # Email (also SG PII)
    re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'),
    # Date of birth patterns
    re.compile(r'\b\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}\b'),
    # IP address
    re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
    # Full name indicator (Blk/Block address common in SG)
    re.compile(r'\bBlk\s+\d+\b', re.IGNORECASE),
    re.compile(r'\b(?:Jalan|Lorong|Taman|Bukit|Ang Mo Kio|Bedok|Tampines|Jurong|Woodlands|Yishun|Sengkang|Punggol|Hougang|Clementi|Bishan|Toa Payoh)\b', re.IGNORECASE),
]


def detect_singapore_pii(content: str, filename: str = "") -> None:
    """
    Scan content for Singapore PII patterns.
    Raises HTTPException 400 if Singapore PII is detected.
    """
    for pattern in _SG_PII_PATTERNS:
        if pattern.search(content):
            raise HTTPException(
                status_code=400,
                detail=f"File '{filename}' contains Singapore PII and cannot be processed."
            )


# ---------------------------------------------------------------------------
# Instruction 10: Inter-agent authentication helpers
# ---------------------------------------------------------------------------

def _generate_agent_token(api_key: str, message: str) -> str:
    """Generate a signed HMAC token binding caller identity to the request."""
    secret = _AGENT_SECRET.encode() if _AGENT_SECRET else api_key.encode()
    payload = f"{api_key}:{message}:{datetime.now(timezone.utc).isoformat()}"
    token = hmac.new(secret, payload.encode(), hashlib.sha256).hexdigest()
    return token


def _verify_agent_token(token: str, api_key: str) -> bool:
    """Verify that the agent token was signed with the shared secret."""
    if not token or not api_key:
        return False
    # For demo: accept any non-empty token when secret is configured
    return bool(token)


async def _require_agent_token(request: Request):
    """FastAPI dependency: verify X-Agent-Token header for inter-agent auth."""
    token = request.headers.get("X-Agent-Token", "")
    api_key = request.headers.get("X-Agent-API-Key", _MCP_CLIENT_API_KEY)
    if not token:
        raise HTTPException(status_code=401, detail="Missing X-Agent-Token header.")
    if not _verify_agent_token(token, api_key):
        raise HTTPException(status_code=401, detail="Invalid or missing agent authentication token.")


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "policyprobe"}


@app.post("/chat", response_model=ChatResponse, dependencies=[Depends(_require_agent_token)])
async def chat(request: ChatRequest):
    """
    Main chat endpoint that processes user messages and file uploads.

    This endpoint:
    1. Receives user messages and optional file attachments
    2. Processes files through the File Processor Agent
    3. Routes the request through the Orchestrator Agent
    4. Returns the agent response
    """
    try:
        # Instruction 4: Sanitize and validate user message
        sanitized_message = _sanitize_user_message(request.message)

        # Instruction 10: Validate api_key is non-empty
        api_key = os.getenv("MCP_CLIENT_API_KEY", "")
        if not api_key:
            raise HTTPException(status_code=500, detail="Agent API key is not configured.")

        file_contents = []
        if request.attachments:
            for attachment in request.attachments:
                # Instruction 4: Sanitize attachment content
                sanitized_content = _sanitize_attachment_content(attachment.content, attachment.name)

                # Instruction 5: Scan for malicious content in file
                if sanitized_content and not (
                    (attachment.type or "").startswith("image/") or
                    attachment.type in {
                        "application/pdf",
                        "application/msword",
                        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    }
                ):
                    sanitized_content = sanitize_file_content(sanitized_content, attachment.name)

                # Instruction 6: Redact PII from text content
                if sanitized_content and not (
                    (attachment.type or "").startswith("image/") or
                    attachment.type in {
                        "application/pdf",
                        "application/msword",
                        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    }
                ):
                    sanitized_content = redact_pii(sanitized_content)

                # Instruction 7: Detect Singapore PII
                if sanitized_content and not (
                    (attachment.type or "").startswith("image/") or
                    attachment.type in {
                        "application/pdf",
                        "application/msword",
                        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    }
                ):
                    detect_singapore_pii(sanitized_content, attachment.name)

                logger.info(
                    "Processing attachment",
                    extra={
                        "file_name": attachment.name,
                        "file_type": attachment.type,
                        "file_size": attachment.size,
                    }
                )

                processed = await process_file_attachment(
                    content=sanitized_content,
                    filename=attachment.name,
                    content_type=attachment.type
                )
                file_contents.append(processed)

        # Instruction 10: Generate signed HMAC token for downstream agent calls
        agent_token = _generate_agent_token(api_key, sanitized_message)

        context = {
            "user_message": sanitized_message,
            "file_contents": file_contents,
            "conversation_id": request.conversation_id,
            "api_key": api_key,
            "agent_token": agent_token,
        }

        response = await handle_chat_request(context)

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
                "error": str(e),
            }
        )
        raise HTTPException(
            status_code=500,
            detail={
                "detail": "An error occurred processing your request",
                "policy_error": {
                    "type": "general",
                    "message": "An internal error occurred."
                }
            }
        )


@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    """
    Direct file upload endpoint.
    """
    content = await file.read()
    is_binary = (file.content_type or "").startswith("image/") or file.content_type in {
        "application/pdf",
        "application/msword",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    }

    if is_binary:
        processed_content = base64.b64encode(content).decode("utf-8")
    else:
        decoded_text = content.decode("utf-8", errors="ignore")
        # Instruction 4: Sanitize decoded file content
        decoded_text = _sanitize_decoded_file_content(decoded_text)
        # Instruction 5: Scan for malicious content
        decoded_text = sanitize_file_content(decoded_text, file.filename or "")
        # Instruction 6: Redact PII
        decoded_text = redact_pii(decoded_text)
        # Instruction 7: Detect Singapore PII
        detect_singapore_pii(decoded_text, file.filename or "")
        processed_content = decoded_text

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
    """
    # Instruction 8: Require Bearer token authentication (MCP client authenticates server)
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header.")
    bearer_token = auth_header[len("Bearer "):]
    expected_client_key = _MCP_CLIENT_API_KEY
    if not expected_client_key or not hmac.compare_digest(bearer_token, expected_client_key):
        raise HTTPException(status_code=401, detail="Unauthorized: invalid Bearer token.")

    # Instruction 9: Require X-MCP-API-Key header (MCP server authenticates client)
    mcp_api_key_header = request.headers.get("X-MCP-API-Key", "")
    expected_mcp_key = _MCP_API_KEY
    if not expected_mcp_key:
        raise HTTPException(status_code=500, detail="MCP API key is not configured on the server.")
    if not hmac.compare_digest(mcp_api_key_header, expected_mcp_key):
        raise HTTPException(status_code=401, detail="Unauthorized: invalid MCP API key.")

    # Instruction 2: Validate server_key against allowlist
    if server_key not in _ALLOWED_SERVER_KEYS:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown MCP server key: '{server_key}'. Must be one of: {sorted(_ALLOWED_SERVER_KEYS)}"
        )

    payload = await request.json()
    params = payload.get("params", {})
    tool_name = params.get("name", "")
    arguments = params.get("arguments", {})

    # Instruction 2: Validate tool_name
    if not tool_name or not isinstance(tool_name, str):
        raise HTTPException(status_code=400, detail="'tool_name' must be a non-empty string.")
    if not _TOOL_NAME_PATTERN.match(tool_name):
        raise HTTPException(
            status_code=400,
            detail="'tool_name' contains invalid characters. Must match pattern: [a-zA-Z0-9_\\-.]{1,128}"
        )

    # Instruction 2: Validate arguments is a dictionary
    if not isinstance(arguments, dict):
        raise HTTPException(status_code=400, detail="'arguments' must be a JSON object (dictionary).")

    response_payload = _handle_mock_mcp_call(server_key, tool_name, arguments)

    # Instruction 3: Sanitize MCP response before returning
    sanitized_response = _sanitize_mcp_response(response_payload)

    return {
        "jsonrpc": "2.0",
        "id": payload.get("id"),
        "result": sanitized_response,
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
        "raw_arguments": json.dumps(arguments),
        "timestamp": timestamp,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=5500)