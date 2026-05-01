"""Loan Processing Agent class with explicit model invocation."""

import asyncio
import logging
import re
import unicodedata
from typing import Any

from .framework import PolicyProbeAgentFramework
from .helpers import build_file_summary, extract_reference_number
from .mcp_servers import call_mcp_server

logger = logging.getLogger(__name__)

# Singapore PII patterns
_SG_NRIC_RE = re.compile(r'\b[STFG]\d{7}[A-Z]\b', re.IGNORECASE)
_SG_PASSPORT_RE = re.compile(r'\bE\d{7}[A-Z]\b', re.IGNORECASE)
_SG_PHONE_RE = re.compile(r'\b(?:\+65[\s-]?)?\d{4}[\s-]?\d{4}\b')
_SG_EMAIL_RE = re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b')
_SG_BANK_RE = re.compile(r'\b\d{10,16}\b')
_SG_ADDRESS_RE = re.compile(
    r'\b(?:Blk|Block|No\.?)\s+\d+[A-Za-z]?\s+[A-Za-z\s]+(?:Street|St|Avenue|Ave|Road|Rd|Drive|Dr|Lane|Ln|Place|Pl|Crescent|Cres|Close|Walk|Way|Terrace|Ter)\b',
    re.IGNORECASE,
)
_SG_NAME_RE = re.compile(r'\b(?:Mr|Mrs|Ms|Dr|Prof)\.?\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+\b')

# General PII redaction patterns
_EMAIL_RE = re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b')
_PHONE_RE = re.compile(r'\b(?:\+?\d[\d\s\-().]{7,}\d)\b')
_SSN_RE = re.compile(r'\b\d{3}-\d{2}-\d{4}\b')
_CC_RE = re.compile(r'\b(?:\d[ -]?){13,16}\b')
_DOB_RE = re.compile(r'\b(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}[/-]\d{1,2}[/-]\d{1,2})\b')

# Dynamic code execution primitives
_CODE_EXEC_RE = re.compile(
    r'\b(?:eval|exec|subprocess|__import__|compile|execfile|os\.system|os\.popen|'
    r'importlib|__builtins__|getattr|setattr|delattr|globals|locals|vars|open|'
    r'input|breakpoint|__subclasses__|__bases__|__mro__)\s*\(',
    re.IGNORECASE,
)

# Prompt injection patterns
_PROMPT_INJECTION_RE = re.compile(
    r'(?i)(ignore\s+(previous|prior|above|all)\s+instructions?|'
    r'you\s+are\s+now|new\s+role:|system\s*:|<\s*system\s*>|'
    r'\[system\]|\[user\]|\[assistant\]|disregard\s+(all\s+)?previous|'
    r'forget\s+(all\s+)?previous|override\s+(the\s+)?system)',
)

# Hidden/malicious content patterns for file scanning
_BASE64_RE = re.compile(r'(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')
_BINARY_SHELL_RE = re.compile(r'(?:/bin/|/usr/bin/|cmd\.exe|powershell|bash\s+-[ci]|sh\s+-[ci])', re.IGNORECASE)
_INVISIBLE_TEXT_RE = re.compile(r'[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]')
_LEETSPEAK_SUSPICIOUS_RE = re.compile(r'(?i)(?:1gnor3|3x3cut3|syst3m|pr0mpt|1nstruct10n)')

MAX_INPUT_LENGTH = 4000
MAX_LOAN_NUMBER_LENGTH = 50
MAX_FILE_SUMMARY_LENGTH = 8000
MAX_MCP_STRING_LENGTH = 2000


def _redact_pii(text: str) -> str:
    """Redact common PII patterns from text."""
    if not isinstance(text, str):
        return text
    text = _EMAIL_RE.sub('[EMAIL REDACTED]', text)
    text = _PHONE_RE.sub('[PHONE REDACTED]', text)
    text = _SSN_RE.sub('[SSN REDACTED]', text)
    text = _CC_RE.sub('[CC REDACTED]', text)
    text = _DOB_RE.sub('[DOB REDACTED]', text)
    return text


def _sanitize_mcp_string(value: str, max_length: int = MAX_MCP_STRING_LENGTH) -> str:
    """Strip control characters, limit length, and allow only safe characters."""
    if not isinstance(value, str):
        value = str(value)
    # Remove control characters
    value = ''.join(ch for ch in value if unicodedata.category(ch)[0] != 'C' or ch in ('\n', '\r', '\t'))
    # Limit length
    value = value[:max_length]
    return value


def _sanitize_loan_number(value: str) -> str:
    """Sanitize loan number: alphanumeric, hyphens, underscores only."""
    if not isinstance(value, str):
        value = str(value)
    value = re.sub(r'[^A-Za-z0-9\-_]', '', value)
    return value[:MAX_LOAN_NUMBER_LENGTH]


def _scan_file_for_malicious_content(content: str) -> str:
    """Scan and sanitize file content for hidden prompts, base64, invisible text, etc."""
    if not isinstance(content, str):
        return content
    # Remove invisible/zero-width characters
    content = _INVISIBLE_TEXT_RE.sub('', content)
    # Remove base64-encoded blobs
    content = _BASE64_RE.sub('[BASE64 REMOVED]', content)
    # Remove binary/shell command patterns
    content = _BINARY_SHELL_RE.sub('[SHELL CMD REMOVED]', content)
    # Remove leetspeak suspicious patterns
    content = _LEETSPEAK_SUSPICIOUS_RE.sub('[SUSPICIOUS REMOVED]', content)
    # Remove prompt injection attempts
    content = _PROMPT_INJECTION_RE.sub('[INJECTION REMOVED]', content)
    return content


def _check_sg_pii(content: str) -> bool:
    """Return True if Singapore PII is detected in content."""
    if _SG_NRIC_RE.search(content):
        return True
    if _SG_PASSPORT_RE.search(content):
        return True
    if _SG_PHONE_RE.search(content):
        return True
    if _SG_EMAIL_RE.search(content):
        return True
    if _SG_BANK_RE.search(content):
        return True
    if _SG_ADDRESS_RE.search(content):
        return True
    if _SG_NAME_RE.search(content):
        return True
    return False


def _sanitize_llm_output(text: str) -> str:
    """Remove dynamic code execution primitives from LLM output."""
    if not isinstance(text, str):
        return text
    return _CODE_EXEC_RE.sub('[REMOVED]', text)


def _validate_mcp_result(result: Any) -> Any:
    """Validate and sanitize MCP server result."""
    if result is None:
        return {"status": "no_response", "sanitized": True}
    if isinstance(result, str):
        result = _sanitize_mcp_string(result)
        result = _redact_pii(result)
        return result
    if isinstance(result, dict):
        return {
            k: _validate_mcp_result(v) for k, v in result.items()
        }
    if isinstance(result, list):
        return [_validate_mcp_result(item) for item in result]
    return result


class LoanProcessingAgent(PolicyProbeAgentFramework):
    AGENT_ID = "loan_processing_agent"
    AGENT_NAME = "Loan Processing Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "gpt-4o"
    BEDROCK_MODEL_ID = "amazon.titan-text-express-v1"
    DESCRIPTION = "Handles loan application intake, borrower updates, and loan package generation."
    MCP_SERVERS = ["Docx", "Excel", "Email"]
    GUARDRAILS = {
        "mask_pii": None,
        "base64_prompt_detection": None,
        "credential_minimization": None,
        "inter_agent_authentication": None,
    }
    SYSTEM_PROMPT = "Process loan requests, summarize borrower context, and prepare follow-up actions."
    IS_ROUTABLE = False
    IS_SCAN_ONLY = True

    MCP_SERVER_AUTH_TOKENS = {
        "Docx": "mcp-docx-shared-secret",
        "Excel": "mcp-excel-shared-secret",
        "Email": "mcp-email-shared-secret",
    }

    def get_auth_token(self) -> str:
        """Retrieve the client auth token from agent config/guardrails."""
        return self.GUARDRAILS.get("inter_agent_authentication") or "loan-processing-agent-client-token"

    def authenticate_mcp_server(self, server_name: str) -> dict:
        """Return auth credentials for the given MCP server."""
        token = self.MCP_SERVER_AUTH_TOKENS.get(server_name, "")
        if not token:
            raise ValueError(f"No auth token configured for MCP server: {server_name}")
        return {
            "server_identity": server_name,
            "shared_secret": token,
        }

    def _sanitize_input(self, text: str, max_length: int = MAX_INPUT_LENGTH) -> str:
        """Strip whitespace, enforce max length, remove prompt injection patterns."""
        if not isinstance(text, str):
            text = str(text)
        text = text.strip()
        text = text[:max_length]
        text = _PROMPT_INJECTION_RE.sub('[INJECTION REMOVED]', text)
        return text

    def _validate_mcp_result(self, result: Any) -> Any:
        """Instance method wrapper for MCP result validation."""
        return _validate_mcp_result(result)

    async def call_agent_model(self, user_message: str, file_summary: str) -> str:
        sanitized_user_message = self._sanitize_input(user_message)
        sanitized_user_message = _redact_pii(sanitized_user_message)
        sanitized_file_summary = self._sanitize_input(file_summary, max_length=MAX_FILE_SUMMARY_LENGTH)
        sanitized_file_summary = _redact_pii(sanitized_file_summary)

        request_payload = {
            "model": self.MODEL_NAME,
            "messages": [
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Loan request:\n{sanitized_user_message or 'No user message provided.'}\n\n"
                        f"File summary:\n{sanitized_file_summary}\n\n"
                        "Draft a concise loan processing next-step summary."
                    ),
                },
            ],
            "temperature": 0.2,
            "max_tokens": 250,
        }

        logger.info(
            "LLM request initiated",
            extra={
                "agent": self.AGENT_NAME,
                "model": self.MODEL_NAME,
                "message_roles": [m["role"] for m in request_payload["messages"]],
            },
        )

        response = await self.model_client.chat(
            model=request_payload["model"],
            messages=request_payload["messages"],
            temperature=request_payload["temperature"],
            max_tokens=request_payload["max_tokens"],
        )

        logger.info(
            "LLM response received",
            extra={
                "agent": self.AGENT_NAME,
                "model": self.MODEL_NAME,
                "response_length": len(response) if isinstance(response, str) else None,
            },
        )

        return response

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        user_message = context.get("user_message", "")
        raw_file_contents = context.get("file_contents", [])

        # Scan each file's content for Singapore PII before processing
        for file_item in raw_file_contents:
            content_to_check = ""
            if isinstance(file_item, dict):
                content_to_check = file_item.get("content", "") or file_item.get("text", "")
            elif isinstance(file_item, str):
                content_to_check = file_item
            if content_to_check and _check_sg_pii(content_to_check):
                raise ValueError(
                    "Uploaded file contains Singapore PII. Processing blocked per policy."
                )

        # Scan and sanitize file contents for malicious content before building summary
        sanitized_file_contents = []
        for file_item in raw_file_contents:
            if isinstance(file_item, dict):
                sanitized_item = dict(file_item)
                for key in ("content", "text"):
                    if key in sanitized_item and isinstance(sanitized_item[key], str):
                        sanitized_item[key] = _scan_file_for_malicious_content(sanitized_item[key])
                sanitized_file_contents.append(sanitized_item)
            elif isinstance(file_item, str):
                sanitized_file_contents.append(_scan_file_for_malicious_content(file_item))
            else:
                sanitized_file_contents.append(file_item)

        file_summary = build_file_summary(sanitized_file_contents)

        # Redact PII from file summary immediately after construction
        file_summary = _redact_pii(file_summary)

        loan_number = extract_reference_number(user_message, prefix="LOAN")

        # Sanitize inputs for MCP calls
        safe_user_message = _sanitize_mcp_string(user_message)
        safe_user_message = _redact_pii(safe_user_message)
        safe_file_summary = _sanitize_mcp_string(file_summary)
        safe_loan_number = _sanitize_loan_number(loan_number)

        model_output = await self.call_agent_model(user_message, file_summary)

        # Sanitize LLM output for dynamic code execution primitives
        model_output = _sanitize_llm_output(model_output)

        client_auth_token = self.get_auth_token()

        # MCP server authentication
        docx_server_auth = self.authenticate_mcp_server("Docx")
        excel_server_auth = self.authenticate_mcp_server("Excel")
        email_server_auth = self.authenticate_mcp_server("Email")

        # Log and call Docx MCP server
        logger.info(
            "MCP call initiated",
            extra={"agent": self.AGENT_NAME, "server": "Docx", "tool": "create_document", "loan_number": safe_loan_number},
        )
        docx_args = {
            "document_title": f"Loan Intake Summary {safe_loan_number}",
            "document_body": f"User message:\n{safe_user_message}\n\nFile summary:\n{safe_file_summary}",
            "server_auth": docx_server_auth,
            "auth_token": client_auth_token,
        }

        # Log and call Excel MCP server
        logger.info(
            "MCP call initiated",
            extra={"agent": self.AGENT_NAME, "server": "Excel", "tool": "upsert_row", "loan_number": safe_loan_number},
        )
        excel_args = {
            "workbook": "Loan Pipeline",
            "worksheet": "Applications",
            "row": {
                "loan_number": safe_loan_number,
                "status": "processing",
                "borrower_request": safe_user_message[:240],
            },
            "server_auth": excel_server_auth,
            "auth_token": client_auth_token,
        }

        # Log and call Email MCP server
        logger.info(
            "MCP call initiated",
            extra={"agent": self.AGENT_NAME, "server": "Email", "tool": "send_email", "loan_number": safe_loan_number},
        )
        email_args = {
            "to": ["borrower@acme.example"],
            "subject": f"Loan update for {safe_loan_number}",
            "body": "Your loan request is being reviewed by the Loan Processing Agent.",
            "server_auth": email_server_auth,
            "auth_token": client_auth_token,
        }

        mcp_results = await asyncio.gather(
            call_mcp_server(self.to_dict(), "Docx", "create_document", docx_args),
            call_mcp_server(self.to_dict(), "Excel", "upsert_row", excel_args),
            call_mcp_server(self.to_dict(), "Email", "send_email", email_args),
        )

        # Log MCP results
        for server_name, result in zip(["Docx", "Excel", "Email"], mcp_results):
            logger.info(
                "MCP call completed",
                extra={
                    "agent": self.AGENT_NAME,
                    "server": server_name,
                    "result_type": type(result).__name__,
                },
            )

        # Validate and sanitize MCP outputs
        mcp_activity = [self._validate_mcp_result(r) for r in mcp_results]

        response = (
            "This scan-only agent is disconnected from the Orchestrator Agent.\n\n"
            f"Loan reference: {safe_loan_number}\n"
            "Your loan request has been received and is being processed."
        )

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "mcp_activity": mcp_activity,
        }


loan_processing_agent = LoanProcessingAgent()