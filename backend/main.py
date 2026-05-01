"""
PolicyProbe Backend - FastAPI Application

This entry point exposes the vulnerable multi-agent loan workflow used by the
demo UI. The backend now routes through a central agent catalog so the agent
names, model names, and MCP server names are easy to inspect in source.
"""

import base64
import hashlib
import hmac
import html
import json
import os
import re
import unicodedata
from datetime import datetime, timezone
from pathlib import Path

# Load environment variables from .env file
from dotenv import load_dotenv
env_path = Path(__file__).parent.parent / '.env'
load_dotenv(env_path)

import logging
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException, UploadFile, File, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from agents.runtime import build_catalog as _build_catalog_raw, handle_chat_request, process_file_attachment

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)
MCP_CALL_LOG: list[dict] = []

# Allowlist of known MCP server keys
_ALLOWED_SERVER_KEYS = {"slack", "servicenow", "email", "excel", "docx", "google-calendar"}

# Maximum lengths
_MAX_TOOL_NAME_LENGTH = 128
_MAX_ARGUMENTS_KEYS = 50
_MAX_ARGUMENT_VALUE_LENGTH = 4096
_MAX_MESSAGE_LENGTH = 32768
_MAX_MCP_STRING_LENGTH = 8192

# Shared secrets from environment
_MCP_SHARED_SECRET = os.environ.get("MCP_SHARED_SECRET", "default-mcp-shared-secret-change-me")
_MCP_API_KEY = os.environ.get("MCP_API_KEY", "default-mcp-api-key-change-me")
_AGENT_SHARED_SECRET = os.environ.get("AGENT_SHARED_SECRET", "default-agent-shared-secret-change-me")

# Dynamic code execution primitives to block in LLM output
_DANGEROUS_PRIMITIVES = [
    r'\beval\s*\(',
    r'\bexec\s*\(',
    r'\bsubprocess\b',
    r'\bos\.system\s*\(',
    r'\b__import__\s*\(',
    r'\bcompile\s*\(',
    r'\bexecfile\s*\(',
    r'\bos\.popen\s*\(',
    r'\bos\.exec[lv]',
    r'\bctypes\b',
    r'\bimportlib\b',
]
_DANGEROUS_PATTERN = re.compile('|'.join(_DANGEROUS_PRIMITIVES), re.IGNORECASE)

# Prompt injection patterns
_INJECTION_PATTERNS = [
    r'ignore\s+(all\s+)?(previous|prior|above)\s+instructions?',
    r'disregard\s+(all\s+)?(previous|prior|above)\s+instructions?',
    r'forget\s+(all\s+)?(previous|prior|above)\s+instructions?',
    r'you\s+are\s+now\s+',
    r'act\s+as\s+',
    r'pretend\s+(you\s+are|to\s+be)\s+',
    r'system\s*:\s*',
    r'<\s*system\s*>',
    r'\[system\]',
    r'###\s*instruction',
    r'new\s+instructions?\s*:',
    r'override\s+instructions?',
]
_INJECTION_PATTERN = re.compile('|'.join(_INJECTION_PATTERNS), re.IGNORECASE)

# PII patterns
_PII_PATTERNS = [
    (re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'), '[EMAIL_REDACTED]'),
    (re.compile(r'\b(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'), '[PHONE_REDACTED]'),
    (re.compile(r'\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b'), '[SSN_REDACTED]'),
    (re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b'), '[CC_REDACTED]'),
]

# Singapore PII patterns
_SG_NRIC_PATTERN = re.compile(r'\b[STFGM]\d{7}[A-Z]\b', re.IGNORECASE)
_SG_SINGPASS_PATTERN = re.compile(r'\bsingpass\b', re.IGNORECASE)
_SG_CPF_PATTERN = re.compile(r'\bcpf\s*(?:account)?\s*(?:number)?\s*:?\s*\d{6,10}\b', re.IGNORECASE)
_SG_FULLNAME_PATTERN = re.compile(r'\b(?:name|full\s+name)\s*:\s*[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,4}\b')

# Malicious content patterns
_HIDDEN_PROMPT_PATTERNS = [
    re.compile(r'<!--.*?-->', re.DOTALL),
    re.compile(r'<script[^>]*>.*?</script>', re.DOTALL | re.IGNORECASE),
    re.compile(r'style\s*=\s*["\'][^"\']*(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0)[^"\']*["\']', re.IGNORECASE),
]
_BINARY_SHELL_PATTERN = re.compile(r'(?:/bin/(?:sh|bash|zsh)|cmd\.exe|powershell)', re.IGNORECASE)
_LEETSPEAK_PATTERN = re.compile(r'[1!][Gg][Nn][0Oo][Rr][3Ee]', re.IGNORECASE)


def build_catalog():
    """Wrapper around the raw catalog builder that filters out disallowed LLMs."""
    catalog = _build_catalog_raw()
    disallowed_models = {'deepseek', 'mistral', 'gpt', 'nova', 'amazon.nova', 'custom_llm_client'}

    def _is_disallowed(model_name: str) -> bool:
        if not model_name:
            return False
        model_lower = model_name.lower()
        return any(d in model_lower for d in disallowed_models)

    if 'agents' in catalog:
        catalog['agents'] = [
            agent for agent in catalog['agents']
            if not _is_disallowed(agent.get('model', ''))
        ]

    return catalog


def _generate_agent_token(agent_id: str = "orchestrator") -> str:
    """Generate an HMAC-signed agent identity token."""
    timestamp = str(int(datetime.now(timezone.utc).timestamp()))
    message = f"{agent_id}:{timestamp}"
    signature = hmac.new(
        _AGENT_SHARED_SECRET.encode('utf-8'),
        message.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    token_data = f"{message}:{signature}"
    return base64.b64encode(token_data.encode('utf-8')).decode('utf-8')


def _generate_server_token(server_key: str) -> str:
    """Generate an HMAC-based token for a given server_key."""
    return hmac.new(
        _MCP_SHARED_SECRET.encode('utf-8'),
        server_key.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()


def _sanitize_input(text: str, max_length: int = _MAX_MESSAGE_LENGTH) -> str:
    """Strip null bytes, enforce max length, and remove prompt injection patterns."""
    if not isinstance(text, str):
        return ""
    # Remove null bytes
    text = text.replace('\x00', '')
    # Enforce max length
    text = text[:max_length]
    # Remove prompt injection patterns
    text = _INJECTION_PATTERN.sub('[FILTERED]', text)
    return text


def _redact_pii(text: str) -> str:
    """Redact common PII patterns from text."""
    if not isinstance(text, str):
        return text
    for pattern, placeholder in _PII_PATTERNS:
        text = pattern.sub(placeholder, text)
    return text


def _detect_singapore_pii(content: str) -> bool:
    """Detect Singapore-specific PII in content."""
    if not isinstance(content, str):
        return False
    if _SG_NRIC_PATTERN.search(content):
        return True
    if _SG_SINGPASS_PATTERN.search(content):
        return True
    if _SG_CPF_PATTERN.search(content):
        return True
    if _SG_FULLNAME_PATTERN.search(content):
        return True
    return False


def scan_for_malicious_content(content: str) -> bool:
    """
    Scan file content for malicious patterns including hidden prompts,
    invisible text, base64-encoded prompts, leetspeak, suspicious instructions,
    and binary/shell payloads.
    Returns True if malicious content is detected.
    """
    if not isinstance(content, str):
        return False

    # Check for hidden HTML prompts / invisible text
    for pattern in _HIDDEN_PROMPT_PATTERNS:
        if pattern.search(content):
            return True

    # Check for binary/shell payloads
    if _BINARY_SHELL_PATTERN.search(content):
        return True

    # Check for leetspeak injection
    if _LEETSPEAK_PATTERN.search(content):
        return True

    # Check for injection patterns
    if _INJECTION_PATTERN.search(content):
        return True

    # Check for base64-encoded prompts (try to decode and scan)
    b64_candidates = re.findall(r'[A-Za-z0-9+/]{40,}={0,2}', content)
    for candidate in b64_candidates:
        try:
            decoded = base64.b64decode(candidate).decode('utf-8', errors='ignore')
            if _INJECTION_PATTERN.search(decoded):
                return True
        except Exception:
            pass

    return False


def _check_llm_response_for_dangerous_code(response_text: str) -> None:
    """
    Check LLM response text for dynamic code execution primitives.
    Raises HTTP 400 if any are detected.
    """
    if _DANGEROUS_PATTERN.search(response_text):
        raise HTTPException(
            status_code=400,
            detail={
                "detail": "LLM response contains potentially dangerous code execution primitives",
                "policy_error": {
                    "type": "dangerous_code",
                    "message": "Response blocked due to presence of dynamic code execution primitives."
                }
            }
        )


def _sanitize_mcp_string(value: str, max_length: int = _MAX_MCP_STRING_LENGTH) -> str:
    """Sanitize a string from MCP response: strip control chars, limit length, HTML-escape."""
    if not isinstance(value, str):
        return value
    # Strip control characters
    value = ''.join(ch for ch in value if not unicodedata.category(ch).startswith('C') or ch in ('\n', '\r', '\t'))
    # Limit length
    value = value[:max_length]
    # HTML-escape
    value = html.escape(value)
    return value


def _sanitize_mcp_response(obj, depth: int = 0):
    """Recursively sanitize all string values in an MCP response object."""
    if depth > 10:
        return obj
    if isinstance(obj, str):
        return _sanitize_mcp_string(obj)
    elif isinstance(obj, dict):
        return {k: _sanitize_mcp_response(v, depth + 1) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_sanitize_mcp_response(item, depth + 1) for item in obj]
    return obj


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


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "policyprobe"}


@app.post("/chat", response_model=ChatResponse)
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
        # Sanitize and validate the user message before sending to AI model
        sanitized_message = _sanitize_input(request.message)

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
                            "message": sanitized_message,
                            "attachment_content_preview": attachment.content[:100] if attachment.content else None
                        }
                    }
                )

                # Sanitize attachment content before processing
                sanitized_content = _sanitize_input(attachment.content) if attachment.content else attachment.content

                # Scan for malicious content in uploaded file
                if sanitized_content and scan_for_malicious_content(sanitized_content):
                    raise HTTPException(
                        status_code=400,
                        detail={
                            "detail": "Malicious content detected in uploaded file",
                            "policy_error": {
                                "type": "malicious_content",
                                "message": f"File '{attachment.name}' contains potentially malicious content."
                            }
                        }
                    )

                # Detect Singapore PII in attachment content
                if sanitized_content and _detect_singapore_pii(sanitized_content):
                    raise HTTPException(
                        status_code=422,
                        detail={
                            "detail": "Singapore PII detected in uploaded file",
                            "policy_error": {
                                "type": "singapore_pii",
                                "message": f"File '{attachment.name}' contains Singapore PII and cannot be processed."
                            }
                        }
                    )

                # Redact PII from attachment content
                if sanitized_content:
                    sanitized_content = _redact_pii(sanitized_content)

                # Generate agent authentication token for inter-agent communication
                agent_token = _generate_agent_token("chat-endpoint")

                processed = await process_file_attachment(
                    content=sanitized_content,
                    filename=attachment.name,
                    content_type=attachment.type,
                    agent_token=agent_token,
                )
                file_contents.append(processed)

        context = {
            "user_message": sanitized_message,
            "file_contents": file_contents,
            "conversation_id": request.conversation_id,
            "agent_token": _generate_agent_token("chat-endpoint"),
        }

        logger.info(
            "Sending request to LLM via handle_chat_request",
            extra={
                "user_message": sanitized_message,
                "conversation_id": request.conversation_id,
                "file_count": len(file_contents),
            }
        )

        response = await handle_chat_request(context)

        logger.info(
            "Received response from LLM via handle_chat_request",
            extra={
                "conversation_id": request.conversation_id,
                "response_preview": str(response.get("response", ""))[:200],
            }
        )

        response_text = response.get("response", "I processed your request.")

        # Validate LLM output for dangerous code execution primitives
        _check_llm_response_for_dangerous_code(response_text)

        return ChatResponse(
            response=response_text,
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
    if (file.content_type or "").startswith("image/") or file.content_type in {
        "application/pdf",
        "application/msword",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    }:
        processed_content = base64.b64encode(content).decode("utf-8")
    else:
        processed_content = content.decode("utf-8", errors="ignore")

    # Sanitize content before processing
    processed_content = _sanitize_input(processed_content)

    # Scan for malicious content in uploaded file
    if scan_for_malicious_content(processed_content):
        raise HTTPException(
            status_code=400,
            detail={
                "detail": "Malicious content detected in uploaded file",
                "policy_error": {
                    "type": "malicious_content",
                    "message": f"File '{file.filename}' contains potentially malicious content."
                }
            }
        )

    # Detect Singapore PII in uploaded file
    if _detect_singapore_pii(processed_content):
        raise HTTPException(
            status_code=422,
            detail={
                "detail": "Singapore PII detected in uploaded file",
                "policy_error": {
                    "type": "singapore_pii",
                    "message": f"File '{file.filename}' contains Singapore PII and cannot be processed."
                }
            }
        )

    # Redact PII from file content
    processed_content = _redact_pii(processed_content)

    # Generate agent authentication token for inter-agent communication
    agent_token = _generate_agent_token("upload-endpoint")

    processed = await process_file_attachment(
        content=processed_content,
        filename=file.filename,
        content_type=file.content_type,
        agent_token=agent_token,
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
    # MCP server authentication: verify client API key
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized: Missing or invalid Authorization header")
    provided_api_key = auth_header[len("Bearer "):]
    if not hmac.compare_digest(provided_api_key, _MCP_API_KEY):
        raise HTTPException(status_code=401, detail="Unauthorized: Invalid API key")

    # MCP client authenticates the server: verify server token
    provided_server_token = request.headers.get("X-MCP-Server-Token", "")
    expected_server_token = _generate_server_token(server_key)
    if not hmac.compare_digest(provided_server_token, expected_server_token):
        raise HTTPException(status_code=401, detail="Unauthorized: Invalid MCP server token")

    # Validate server_key against allowlist
    if server_key not in _ALLOWED_SERVER_KEYS:
        raise HTTPException(status_code=400, detail=f"Unknown MCP server key: {server_key}")

    payload = await request.json()

    # Sanitize the id field from the payload
    raw_id = payload.get("id")
    if isinstance(raw_id, str):
        sanitized_id = _sanitize_mcp_string(raw_id)
    else:
        sanitized_id = raw_id

    params = payload.get("params", {})
    tool_name = params.get("name", "")

    # Validate tool_name: non-empty, within length limit, safe characters only
    if not tool_name or not isinstance(tool_name, str):
        raise HTTPException(status_code=400, detail="Invalid tool_name: must be a non-empty string")
    if len(tool_name) > _MAX_TOOL_NAME_LENGTH:
        raise HTTPException(status_code=400, detail=f"Invalid tool_name: exceeds maximum length of {_MAX_TOOL_NAME_LENGTH}")
    if not re.match(r'^[A-Za-z0-9_.\-]+$', tool_name):
        raise HTTPException(status_code=400, detail="Invalid tool_name: contains unsafe characters")

    arguments = params.get("arguments", {})

    # Validate arguments: must be a dict with bounded size
    if not isinstance(arguments, dict):
        raise HTTPException(status_code=400, detail="Invalid arguments: must be a dictionary")
    if len(arguments) > _MAX_ARGUMENTS_KEYS:
        raise HTTPException(status_code=400, detail=f"Invalid arguments: too many keys (max {_MAX_ARGUMENTS_KEYS})")
    for k, v in arguments.items():
        if isinstance(v, str) and len(v) > _MAX_ARGUMENT_VALUE_LENGTH:
            raise HTTPException(status_code=400, detail=f"Invalid arguments: value for key '{k}' exceeds maximum length")

    response_payload = _handle_mock_mcp_call(server_key, tool_name, arguments)

    # Sanitize MCP server output before returning to caller
    sanitized_response = _sanitize_mcp_response(response_payload)

    return {
        "jsonrpc": "2.0",
        "id": sanitized_id,
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