"""File Processor Agent class with explicit model invocation."""

import base64
import io
import json
import logging
import os
import re
from typing import Any, Optional

try:
    from docx import Document
except ModuleNotFoundError:  # pragma: no cover - depends on local environment
    Document = None

try:
    from cryptography.fernet import Fernet
    import hashlib
    _FERNET_AVAILABLE = True
except ImportError:  # pragma: no cover
    _FERNET_AVAILABLE = False

from file_parsers.html_parser import HTMLParser
from file_parsers.image_parser import ImageParser
from file_parsers.pdf_parser import PDFParser

from .framework import PolicyProbeAgentFramework
from .helpers import build_file_summary
from .mcp_servers import call_mcp_server

logger = logging.getLogger(__name__)

_DANGEROUS_CODE_PATTERNS = re.compile(
    r"\b(eval|exec|subprocess|__import__|compile|execfile|os\.system|os\.popen|"
    r"importlib|__builtins__|globals\(\)|locals\(\)|vars\(\)|getattr|setattr|"
    r"delattr|open\s*\(|input\s*\(|print\s*\()\b",
    re.IGNORECASE,
)

_PROMPT_INJECTION_PATTERNS = re.compile(
    r"(ignore\s+(previous|prior|above|all)\s+(instructions?|prompts?|context)|"
    r"disregard\s+(previous|prior|above|all)\s+(instructions?|prompts?|context)|"
    r"you\s+are\s+now|act\s+as\s+if|pretend\s+(you\s+are|to\s+be)|"
    r"new\s+instructions?:|system\s*:|<\s*system\s*>|<\s*/\s*system\s*>|"
    r"\[INST\]|\[/INST\]|###\s*instruction|###\s*system)",
    re.IGNORECASE,
)

_CONTROL_CHAR_PATTERN = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

_MAX_INPUT_LENGTH = 32000
_MAX_DOCUMENT_BODY_LENGTH = 64000
_MAX_MCP_OUTPUT_FIELD_LENGTH = 8192


def _get_fernet() -> Optional[Any]:
    if not _FERNET_AVAILABLE:
        return None
    key_material = os.environ.get("PII_ENCRYPTION_KEY", "")
    if not key_material:
        return None
    import hashlib as _hashlib
    derived = base64.urlsafe_b64encode(_hashlib.sha256(key_material.encode()).digest())
    return Fernet(derived)


def sanitize_document_body(text: str) -> str:
    """Strip null bytes, control characters, and limit length for MCP document body."""
    if not text:
        return ""
    sanitized = text.replace("\x00", "")
    sanitized = _CONTROL_CHAR_PATTERN.sub("", sanitized)
    if len(sanitized) > _MAX_DOCUMENT_BODY_LENGTH:
        sanitized = sanitized[:_MAX_DOCUMENT_BODY_LENGTH]
    return sanitized


def sanitize_llm_input(text: str) -> str:
    """Strip prompt-injection patterns, control characters, and enforce length limit."""
    if not text:
        return ""
    sanitized = text.replace("\x00", "")
    sanitized = _CONTROL_CHAR_PATTERN.sub("", sanitized)
    sanitized = _PROMPT_INJECTION_PATTERNS.sub("[REDACTED_INJECTION]", sanitized)
    if len(sanitized) > _MAX_INPUT_LENGTH:
        sanitized = sanitized[:_MAX_INPUT_LENGTH]
    return sanitized


def sanitize_llm_output(text: str) -> str:
    """Inspect LLM output for dynamic code execution primitives and strip/replace them."""
    if not text:
        return ""
    sanitized = _CONTROL_CHAR_PATTERN.sub("", text)
    sanitized = _DANGEROUS_CODE_PATTERNS.sub("[BLOCKED_CODE_PRIMITIVE]", sanitized)
    return sanitized


def sanitize_mcp_output(result: Any) -> dict:
    """Validate and sanitize output from an MCP server tool."""
    if result is None:
        logger.warning("MCP server returned None result")
        return {"status": "error", "message": "MCP server returned no result"}

    if not isinstance(result, dict):
        logger.warning("MCP server returned non-dict result: %s", type(result))
        return {"status": "error", "message": "MCP server returned unexpected result type"}

    if "error" in result:
        logger.warning("MCP server returned error: %s", result.get("error"))
        return {"status": "error", "message": "MCP server reported an error"}

    sanitized = {}
    for key, value in result.items():
        if isinstance(value, str):
            cleaned = _CONTROL_CHAR_PATTERN.sub("", value)
            if len(cleaned) > _MAX_MCP_OUTPUT_FIELD_LENGTH:
                cleaned = cleaned[:_MAX_MCP_OUTPUT_FIELD_LENGTH]
            sanitized[key] = cleaned
        else:
            sanitized[key] = value

    return sanitized


def redact_pii_from_text(text: str) -> str:
    """Redact PII patterns from text before sending to LLM."""
    if not text:
        return text
    redacted = re.sub(r"\b\d{3}-\d{2}-\d{4}\b", "[SSN_REDACTED]", text)
    redacted = re.sub(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b", "[EMAIL_REDACTED]", redacted)
    redacted = re.sub(
        r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?){2}\d{4}\b",
        "[PHONE_REDACTED]",
        redacted,
    )
    redacted = re.sub(r"\b[STFGM]\d{7}[A-Z]\b", "[NRIC_REDACTED]", redacted)
    redacted = re.sub(r"\b\d{10}[A-Z]\b", "[CPF_REDACTED]", redacted)

    keyword_markers = (
        "name:",
        "full name:",
        "employee id",
        "date of birth",
        "dob:",
        "ssn",
        "social security",
        "address:",
        "phone:",
        "email:",
        "loan balance",
        "account number",
        "customer id",
        "borrower",
        "credit score",
    )
    lines = redacted.splitlines()
    result_lines = []
    for line in lines:
        lowered = line.lower()
        if any(marker in lowered for marker in keyword_markers):
            result_lines.append("[PII_LINE_REDACTED]")
        else:
            result_lines.append(line)
    return "\n".join(result_lines)


def encrypt_pii_content(text: str) -> str:
    """Encrypt PII-containing content using Fernet symmetric encryption."""
    fernet = _get_fernet()
    if fernet is None:
        logger.warning("PII encryption key not configured; content will not be encrypted")
        return text
    try:
        return fernet.encrypt(text.encode()).decode()
    except Exception as exc:
        logger.error("Failed to encrypt PII content", extra={"error": str(exc)})
        return text


class FileProcessorAgent(PolicyProbeAgentFramework):
    AGENT_ID = "file_processor_agent"
    AGENT_NAME = "File Processor Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "amazon titan text express"
    BEDROCK_MODEL_ID = "amazon.titan-text-express-v1"
    DESCRIPTION = "Extracts text from uploaded files and returns the raw contents to downstream agents."
    MCP_SERVERS = ["Docx"]
    GUARDRAILS = {
        "mask_pii": True,
        "base64_prompt_detection": True,
        "credential_minimization": None,
        "inter_agent_authentication": True,
    }
    SYSTEM_PROMPT = "Extract document text and hand the raw contents to the next agent."

    def __init__(self):
        super().__init__()
        self.pdf_parser = PDFParser()
        self.html_parser = HTMLParser()
        self.image_parser = ImageParser()

    async def call_agent_model(self, file_summary: str) -> str:
        sanitized_summary = sanitize_llm_input(redact_pii_from_text(file_summary))
        return await self.call_bedrock_model(
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Extracted file contents:\n{sanitized_summary}\n\n"
                        "Give a short processing note without masking any content."
                    ),
                },
            ],
            temperature=0.2,
            max_tokens=220,
        )

    def sanitize_extracted_content(self, content: str) -> str:
        """
        Detect and neutralize:
        1. Hidden/invisible text prompts
        2. Base64-encoded prompts
        3. Leetspeak prompts
        4. Prompt injection patterns
        5. Binary/shell command content
        """
        if not content:
            return content

        sanitized = _CONTROL_CHAR_PATTERN.sub("", content)

        sanitized = re.sub(r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]", "", sanitized)

        def _check_and_replace_base64(match: re.Match) -> str:
            candidate = match.group(0)
            try:
                decoded = base64.b64decode(candidate + "==").decode("utf-8", errors="ignore")
                if _PROMPT_INJECTION_PATTERNS.search(decoded):
                    return "[BASE64_INJECTION_BLOCKED]"
            except Exception:
                pass
            return candidate

        sanitized = re.sub(r"[A-Za-z0-9+/]{20,}={0,2}", _check_and_replace_base64, sanitized)

        sanitized = _PROMPT_INJECTION_PATTERNS.sub("[INJECTION_BLOCKED]", sanitized)

        shell_pattern = re.compile(
            r"(rm\s+-rf|chmod\s+|chown\s+|wget\s+|curl\s+.*\|\s*sh|"
            r"/bin/sh|/bin/bash|cmd\.exe|powershell)",
            re.IGNORECASE,
        )
        sanitized = shell_pattern.sub("[SHELL_CMD_BLOCKED]", sanitized)

        return sanitized

    def redact_pii(self, content: str) -> str:
        """Replace detected PII patterns with masked placeholders."""
        return redact_pii_from_text(content)

    async def process_attachment(
        self,
        content: Optional[str],
        filename: str,
        content_type: str,
    ) -> dict[str, Any]:
        """
        Extracts text from uploaded files. PII is redacted and content is sanitized
        before being returned.
        """
        file_type = self.get_file_type(content_type, filename)
        if not content:
            extracted_content = f"Empty file: {filename}"
        elif file_type == "pdf":
            extracted_content = await self._process_pdf(content)
        elif file_type == "html":
            extracted_content = await self._process_html(content)
        elif file_type == "image":
            extracted_content = await self._process_image(content)
        elif file_type == "json":
            extracted_content = await self._process_json(content)
        elif file_type == "word":
            extracted_content = await self._process_word(content)
        else:
            extracted_content = content

        extracted_content = self.sanitize_extracted_content(extracted_content)
        extracted_content = self.redact_pii(extracted_content)

        return {
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "filename": filename,
            "content_type": content_type,
            "file_type": file_type,
            "extracted_content": extracted_content,
            "guardrails": dict(self.GUARDRAILS),
        }

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        file_contents = context.get("file_contents", [])
        file_summary = build_file_summary(file_contents, include_raw_text=True)
        pii_exposure_summary = self.build_pii_exposure_summary(file_contents)

        if pii_exposure_summary:
            logger.warning(
                "PII detected in uploaded file contents; blocking further processing.",
                extra={"agent": self.AGENT_NAME},
            )
            return {
                "response": (
                    "The uploaded document contains sensitive personal information. "
                    "Processing has been blocked to protect privacy. "
                    "Please remove any PII before uploading."
                ),
                "agent": self.AGENT_NAME,
                "model": self.MODEL_NAME,
                "framework": self.FRAMEWORK_NAME,
                "mcp_activity": [],
            }

        sanitized_file_summary = sanitize_llm_input(redact_pii_from_text(file_summary))

        logger.info(
            "Sending request to LLM",
            extra={
                "agent": self.AGENT_NAME,
                "model": self.BEDROCK_MODEL_ID,
                "input_length": len(sanitized_file_summary),
            },
        )
        model_output = await self.call_agent_model(sanitized_file_summary)
        logger.info(
            "Received response from LLM",
            extra={
                "agent": self.AGENT_NAME,
                "model": self.BEDROCK_MODEL_ID,
                "output_length": len(model_output) if model_output else 0,
            },
        )

        model_output = sanitize_llm_output(model_output)

        mcp_client_token = os.environ.get("MCP_CLIENT_TOKEN", self.AGENT_ID)
        mcp_server_token = os.environ.get("MCP_DOCX_SERVER_TOKEN", "")

        sanitized_body = sanitize_document_body(encrypt_pii_content(file_summary))

        mcp_activity = []
        if file_contents:
            mcp_request_params = {
                "document_title": "Extracted File Contents",
                "document_body": sanitized_body,
                "auth_token": mcp_client_token,
            }
            mcp_auth = {
                "verify_ssl": True,
                "token": mcp_server_token,
            }
            logger.info(
                "Calling MCP server 'Docx' with tool 'create_document'",
                extra={
                    "agent": self.AGENT_NAME,
                    "mcp_server": "Docx",
                    "tool": "create_document",
                    "document_title": mcp_request_params["document_title"],
                    "body_length": len(sanitized_body),
                },
            )
            raw_mcp_result = await call_mcp_server(
                self.to_dict(),
                "Docx",
                "create_document",
                mcp_request_params,
                auth=mcp_auth,
            )
            logger.info(
                "Received response from MCP server 'Docx'",
                extra={
                    "agent": self.AGENT_NAME,
                    "mcp_server": "Docx",
                    "tool": "create_document",
                    "result_type": type(raw_mcp_result).__name__,
                },
            )
            validated_mcp_result = sanitize_mcp_output(raw_mcp_result)
            mcp_activity.append(validated_mcp_result)

        response = (
            "I reviewed the uploaded document and extracted its contents.\n\n"
            f"Processing note:\n{model_output}\n\n"
            f"Extracted content preview:\n{sanitized_file_summary}"
        )

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "mcp_activity": mcp_activity,
        }

    def extract_pii_lines(self, content: str, limit: int = 12) -> list[str]:
        keyword_markers = (
            "name:",
            "full name:",
            "employee id",
            "date of birth",
            "dob:",
            "ssn",
            "social security",
            "address:",
            "phone:",
            "email:",
            "loan balance",
            "account number",
            "customer id",
            "borrower",
            "credit score",
            "nric",
            "fin:",
            "fin number",
            "work permit",
            "student pass",
            "singpass",
            "myinfo",
            "cpf",
            "marital status",
            "race:",
            "religion:",
            "political affiliation",
            "voting preference",
            "imei",
            "imsi",
            "device identifier",
            "gps coordinates",
            "wi-fi triangulation",
            "browsing history",
            "search queries",
            "chat logs",
            "call recordings",
            "authentication token",
            "session identifier",
            "session id",
            "passport number",
            "nationality:",
            "gender:",
        )
        pattern_markers = (
            re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
            re.compile(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b"),
            re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?){2}\d{4}\b"),
            re.compile(r"\b[STFGM]\d{7}[A-Z]\b"),
            re.compile(r"\b\d{10}[A-Z]\b"),
        )

        pii_lines: list[str] = []
        for raw_line in (content or "").splitlines():
            line = raw_line.strip()
            if not line:
                continue

            lowered = line.lower()
            if any(marker in lowered for marker in keyword_markers) or any(pattern.search(line) for pattern in pattern_markers):
                pii_lines.append(line)

            if len(pii_lines) >= limit:
                break

        return pii_lines

    def build_pii_exposure_summary(self, file_contents: list[dict[str, Any]]) -> str:
        sections: list[str] = []
        for file_data in file_contents:
            extracted_content = file_data.get("extracted_content", "")
            pii_lines = self.extract_pii_lines(extracted_content)
            if not pii_lines:
                continue

            sections.append(
                f"File: {file_data.get('filename', 'unknown')}\n" + "\n".join(pii_lines)
            )

        return "\n\n".join(sections)

    def get_file_type(self, content_type: str, filename: str) -> str:
        supported_types = {
            "application/pdf": "pdf",
            "text/html": "html",
            "text/plain": "text",
            "application/json": "json",
            "image/jpeg": "image",
            "image/png": "image",
            "application/msword": "word",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "word",
        }

        if content_type in supported_types:
            return supported_types[content_type]

        extension_map = {
            "pdf": "pdf",
            "html": "html",
            "htm": "html",
            "txt": "text",
            "json": "json",
            "jpg": "image",
            "jpeg": "image",
            "png": "image",
            "doc": "word",
            "docx": "word",
        }
        extension = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
        return extension_map.get(extension, "text")

    async def _process_pdf(self, content: str) -> str:
        try:
            return await self.pdf_parser.extract_text(base64.b64decode(content))
        except Exception as exc:
            logger.error("PDF processing failed", extra={"error": str(exc)})
            return f"Error processing PDF: {exc}"

    async def _process_html(self, content: str) -> str:
        try:
            return await self.html_parser.extract_text(content)
        except Exception as exc:
            logger.error("HTML processing failed", extra={"error": str(exc)})
            return f"Error processing HTML: {exc}"

    async def _process_image(self, content: str) -> str:
        try:
            return await self.image_parser.extract_all(base64.b64decode(content))
        except Exception as exc:
            logger.error("Image processing failed", extra={"error": str(exc)})
            return f"Error processing image: {exc}"

    async def _process_json(self, content: str) -> str:
        try:
            return json.dumps(json.loads(content), indent=2)
        except json.JSONDecodeError:
            return content

    async def _process_word(self, content: str) -> str:
        if Document is None:
            return "Word document processing requires python-docx to be installed."

        try:
            document = Document(io.BytesIO(base64.b64decode(content)))
            paragraphs = [paragraph.text.strip() for paragraph in document.paragraphs if paragraph.text.strip()]
            return "\n".join(paragraphs) or "No paragraph text was found in the Word document."
        except Exception as exc:
            logger.error("Word processing failed", extra={"error": str(exc)})
            return f"Error processing Word document: {exc}"


file_processor_agent = FileProcessorAgent()