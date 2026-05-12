"""File Processor Agent class with explicit model invocation."""

import base64
import io
import json
import logging
import os
import re
from typing import Any, Optional

from cryptography.fernet import Fernet

try:
    from docx import Document
except ModuleNotFoundError:  # pragma: no cover - depends on local environment
    Document = None

from file_parsers.html_parser import HTMLParser
from file_parsers.image_parser import ImageParser
from file_parsers.pdf_parser import PDFParser

from .framework import PolicyProbeAgentFramework
from .helpers import build_file_summary, mask_pii
from .mcp_servers import call_mcp_server
from .config import get_mcp_auth_token

logger = logging.getLogger(__name__)


class FileProcessorAgent(PolicyProbeAgentFramework):
    AGENT_ID = "file_processor_agent"
    AGENT_NAME = "File Processor Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "claude-3-haiku"
BEDROCK_MODEL_ID = "anthropic.claude-3-haiku-20240307-v1:0"
    DESCRIPTION = "Extracts text from uploaded files and returns the raw contents to downstream agents."
    MCP_SERVERS = ["Docx"]
    GUARDRAILS = {
        "mask_pii": False,
        "base64_prompt_detection": None,
        "credential_minimization": None,
        "inter_agent_authentication": None,
    }
    SYSTEM_PROMPT = "Extract document text and hand the raw contents to the next agent."

    def __init__(self):
        super().__init__()
        self.pdf_parser = PDFParser()
        self.html_parser = HTMLParser()
        self.image_parser = ImageParser()

                async def call_agent_model(self, file_summary: str) -> str:
        masked_summary = mask_pii(file_summary)
        return await self.call_bedrock_model(
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Extracted file contents:\n{masked_summary}\n\n"
                        "Give a short processing note without masking any content."
                    ),
                },
            ],
            temperature=0.2,
            max_tokens=220,
        ) -> str:
        # Sanitize input to prevent prompt injection or malicious content
        sanitized_summary = self._sanitize_input(file_summary)
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

    def _sanitize_input(self, text: str) -> str:
        """Sanitize input by removing or escaping potentially dangerous patterns."""
        # Remove any null bytes
        text = text.replace('\x00', '')
        # Escape curly braces to prevent template injection
        text = text.replace('{', '{{').replace('}', '}}')
        # Remove any control characters except newlines and tabs
        text = ''.join(c for c in text if c == '\n' or c == '\t' or (c.isprintable() or c in ('\r',)))
        # Limit length to prevent abuse
        max_length = 10000
        if len(text) > max_length:
            text = text[:max_length]
        return text -> str:
        # Validate and sanitize input before processing
        if not isinstance(file_summary, str) or not file_summary.strip():
            raise ValueError("file_summary must be a non-empty string")
        sanitized_summary = file_summary.strip().replace('\x00', '')
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
        ) -> str:
        logger.info(
            "LLM interaction: agent=%s model=%s messages=%s",
            self.AGENT_NAME,
            self.MODEL_NAME,
            [
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Extracted file contents:\n{file_summary}\n\n"
                        "Give a short processing note without masking any content."
                    ),
                },
            ],
        )
        return await self.call_bedrock_model(
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Extracted file contents:\n{file_summary}\n\n"
                        "Give a short processing note without masking any content."
                    ),
                },
            ],
            temperature=0.2,
            max_tokens=220,
        )

    async def process_attachment(
        self,
        content: Optional[str],
        filename: str,
        content_type: str,
    ) -> dict[str, Any]:
        """
        Vulnerability: extracted text is returned directly without PII masking.
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
            extracted_content = await self._process_word(content, auth_token=get_mcp_auth_token('Docx'))
        else:
            extracted_content = content

        sanitized = self._sanitize_content(extracted_content)
        return {
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "filename": filename,
            "content_type": content_type,
            "file_type": file_type,
            "extracted_content": self.redact_pii(extracted_content),
            "guardrails": dict(self.GUARDRAILS),
            "provenance": {
                "model_id": self.MODEL_NAME,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "origin_tag": "ai-generated",
            },
            "synthetic_content_label": True,
        }

    def _sanitize_mcp_output(self, output: dict[str, Any]) -> dict[str, Any]:
        """Sanitize MCP server output to prevent injection attacks."""
        sanitized: dict[str, Any] = {}
        for key, value in output.items():
            if isinstance(value, str):
                sanitized[key] = html.escape(value)
            elif isinstance(value, dict):
                sanitized[key] = self._sanitize_mcp_output(value)
            elif isinstance(value, list):
                sanitized[key] = [
                    self._sanitize_mcp_output(item) if isinstance(item, dict) else
                    html.escape(item) if isinstance(item, str) else item
                    for item in value
                ]
            else:
                sanitized[key] = value
        return sanitized

        def _sanitize_for_prompt(self, text: str) -> str:
        """Remove or escape characters that could be used for prompt injection or command execution."""
        # Remove control characters except newline and tab
        sanitized = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)
        # Escape backticks to prevent code execution
        sanitized = sanitized.replace('`', '\`')
        # Escape dollar signs to prevent variable expansion
        sanitized = sanitized.replace('$', '\$')
        return sanitized

    def redact_pii(self, text: str) -> str:
        """Redact common PII patterns from text."""
        import re
        # Redact email addresses
        text = re.sub(r'[\w.+-]+@[\w-]+\.[\w.-]+', '[REDACTED EMAIL]', text)
        # Redact phone numbers (simple patterns)
        text = re.sub(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', '[REDACTED PHONE]', text)
        # Redact SSN-like patterns
        text = re.sub(r'\b\d{3}-\d{2}-\d{4}\b', '[REDACTED SSN]', text)
        return text

    def _mask_sg_pii(self, text: str) -> str:
        """Mask Singapore PII categories: NRIC, FIN, passport, name, address, phone, email, DOB."""
        import re
        # NRIC/FIN (e.g., S1234567A, T1234567A, F1234567A, G1234567A, M1234567A)
        text = re.sub(r'[STFGM]\d{7}[A-Z]', '[REDACTED]', text)
        # Passport (e.g., E1234567A, H1234567A, K1234567A, L1234567A, N1234567A, P1234567A, R1234567A, T1234567A)
        text = re.sub(r'[EHKLNPRT]\d{7}[A-Z]', '[REDACTED]', text)
        # Email addresses
        text = re.sub(r'[\w.-]+@[\w.-]+\.\w+', '[REDACTED]', text)
        # Singapore phone numbers (e.g., +65 91234567, 91234567, 81234567)
        text = re.sub(r'(\+65[\s-]?)?[689]\d{7}', '[REDACTED]', text)
        # Date of birth (common formats: DD/MM/YYYY, DD-MM-YYYY, YYYY-MM-DD)
        text = re.sub(r'\b\d{2}/\d{2}/\d{4}\b', '[REDACTED]', text)
        text = re.sub(r'\b\d{2}-\d{2}-\d{4}\b', '[REDACTED]', text)
        text = re.sub(r'\b\d{4}-\d{2}-\d{2}\b', '[REDACTED]', text)
        # Simple name/address/phone/email markers (case-insensitive)
        markers = [
            (r'(?i)(name\s*:\s*).+', r'\1[REDACTED]'),
            (r'(?i)(full name\s*:\s*).+', r'\1[REDACTED]'),
            (r'(?i)(address\s*:\s*).+', r'\1[REDACTED]'),
            (r'(?i)(phone\s*:\s*).+', r'\1[REDACTED]'),
            (r'(?i)(email\s*:\s*).+', r'\1[REDACTED]'),
            (r'(?i)(date of birth\s*:\s*).+', r'\1[REDACTED]'),
            (r'(?i)(dob\s*:\s*).+', r'\1[REDACTED]'),
            (r'(?i)(employee id\s*:\s*).+', r'\1[REDACTED]'),
            (r'(?i)(ssn\s*:\s*).+', r'\1[REDACTED]'),
            (r'(?i)(social security\s*:\s*).+', r'\1[REDACTED]'),
            (r'(?i)(loan balance\s*:\s*).+', r'\1[REDACTED]'),
        ]
        for pattern, replacement in markers:
            text = re.sub(pattern, replacement, text)
        return text

        async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        file_contents = context.get("file_contents", [])
        file_summary = build_file_summary(file_contents, include_raw_text=True, auth_token=context.get("auth_token", ""))
        pii_exposure_summary = self.build_pii_exposure_summary(file_contents)
        model_output = await self.call_agent_model(file_summary)
        # Audit logging for AI-driven decision
        import hashlib, datetime
        audit_record = {
            "model_id": self.MODEL_NAME,
            "input_hash": hashlib.sha256(file_summary.encode()).hexdigest(),
            "output": model_output,
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "principal": context.get("user", "unknown"),
        }
        if not hasattr(self.__class__, '_audit_log'):
            self.__class__._audit_log = []
        self.__class__._audit_log.append(audit_record)
        mcp_activity = (
            [
                await call_mcp_server(
                    self.to_dict(),
                    "Docx",
                    "create_document",
                    {
                        "document_title": "Extracted File Contents",
                        "document_body": file_summary,
                    },
                )
            ]
            if file_contents and "Docx" in self.MCP_SERVERS
            else []
        )

        response = (
            "I reviewed the uploaded document and extracted its contents.\n\n"
            f"Processing note:\n{model_output}\n\n"
            f"Extracted content preview:\n{file_summary}"
        )
        sanitized_summary = self._sanitize_for_prompt(file_summary)
        model_output = await self.call_agent_model(sanitized_summary)
        mcp_activity = [
            await call_mcp_server(
                self.to_dict(),
                "Docx",
                "create_document",
                {
                    "document_title": "Extracted File Contents",
                    "document_body": file_summary,
                },
            )
        ]

        if pii_exposure_summary:
            response = (
                "I reviewed the uploaded document and extracted its contents.\n\n"
                f"Processing note:\n{model_output}\n\n"
                f"Extracted content preview: (minimized)"
            )
        else:
            response = (
                "I reviewed the uploaded document and extracted its contents.\n\n"
                f"Processing note:\n{model_output}\n\n"
                f"Extracted content preview:\n{file_summary}"
            )

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "mcp_activity": mcp_activity,
        },
            ))
        ] if file_contents else []

        if pii_exposure_summary:
            response = (
                "I reviewed the uploaded document and displayed the extracted customer details below.\n\n"
                "Sensitive details shown in the interface:\n"
                f"{pii_exposure_summary}\n\n"
                f"Processing note:\n{model_output}"
            )
        else:
            response = (
                "I reviewed the uploaded document and extracted its contents.\n\n"
                f"Processing note:\n{model_output}\n\n"
                f"Extracted content preview:\n{file_summary}"
            )

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "mcp_activity": mcp_activity,
        }

    def _sanitize_text(self, text: str) -> str:
        """Sanitize text by escaping HTML special characters to prevent injection."""
        import html
        return html.escape(text, quote=True)

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
        )
        pattern_markers = (
            re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
            re.compile(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b"),
            re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?){2}\d{4}\b"),
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

    def _sanitize_content(self, content: str) -> str:
        """Remove or neutralize potential malicious prompt injections."""
        # Remove base64-encoded strings that look like prompts (e.g., long alphanumeric sequences)
        sanitized = re.sub(r'[A-Za-z0-9+/]{40,}={0,2}', '[REDACTED]', content)
        # Remove common hidden prompt markers
        sanitized = sanitized.replace('<!--', '').replace('-->', '')
        sanitized = sanitized.replace('/*', '').replace('*/', '')
        return sanitized

    async def _process_word(self, content: str, auth_token: str = '') -> str:
        if Document is None:
            return "Word document processing requires python-docx to be installed."

        try:
            document = Document(io.BytesIO(base64.b64decode(content)))
            # Note: The actual MCP server call is made elsewhere; this is a placeholder for the authentication token usage.
            # In a real scenario, the token would be passed to call_mcp_server.
            _ = auth_token  # suppress unused variable warning
            paragraphs = [paragraph.text.strip() for paragraph in document.paragraphs if paragraph.text.strip()]
            return "\n".join(paragraphs) or "No paragraph text was found in the Word document."
        except Exception as exc:
            logger.error("Word processing failed", extra={"error": str(exc)})
            return f"Error processing Word document: {exc}"


    def _encrypt_content(self, content: str) -> str:
        """Encrypt content using a symmetric key derived from an environment variable."""
        key = os.environ.get("ENCRYPTION_KEY")
        if not key:
            # Fallback: generate a key (in production, set ENCRYPTION_KEY env var)
            key = Fernet.generate_key().decode()
            os.environ["ENCRYPTION_KEY"] = key
        cipher = Fernet(key.encode())
        return cipher.encrypt(content.encode()).decode()


file_processor_agent = FileProcessorAgent()
