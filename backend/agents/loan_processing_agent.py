"""Loan Processing Agent class with explicit model invocation."""

import asyncio
import html
from typing import Any

from .framework import PolicyProbeAgentFramework
from .helpers import build_file_summary, extract_reference_number, mask_singapore_pii, redact_pii
from typing import List, Dict, Any
import re
import base64
import os
from .mcp_servers import call_mcp_server
from .helpers import log_warning
import logging


def _get_mcp_auth_token() -> str:
    """Retrieve MCP server authentication token from environment."""
    token = os.environ.get("MCP_AUTH_TOKEN")
    if not token:
        raise RuntimeError("MCP_AUTH_TOKEN environment variable not set")
    return token


class LoanProcessingAgent(PolicyProbeAgentFramework):
    _audit_log: list[dict[str, Any]] = []

    AGENT_ID = "loan_processing_agent"
    AGENT_NAME = "Loan Processing Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "gpt-4o"
    BEDROCK_MODEL_ID = ""
    DESCRIPTION = "Handles loan application intake, borrower updates, and loan package generation."
    MCP_SERVERS = ["Docx", "Excel", "Email"]
    ALLOWED_MCP_SERVERS = {"Docx", "Excel", "Email"}
    GUARDRAILS = {
        "mask_pii": None,
        "base64_prompt_detection": None,
        "credential_minimization": None,
        "inter_agent_authentication": None,
    }
    SYSTEM_PROMPT = "Process loan requests, summarize borrower context, and prepare follow-up actions."
    IS_ROUTABLE = False
    IS_SCAN_ONLY = True

            @staticmethod
    def _sanitize_input(text: str, max_length: int = 2000) -> str:
        """Sanitize and validate input before sending to LLM."""
        # Remove control characters except newline and tab
        import re
        sanitized = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)
        # Limit length
        sanitized = sanitized[:max_length]
        return sanitized

        @staticmethod
    def _sanitize_input(text: str) -> str:
        """Remove or escape potentially dangerous content from user input."""
        # Remove base64-like strings (alphanumeric with padding)
        import re
        text = re.sub(r'[A-Za-z0-9+/=]{20,}', '[REDACTED]', text)
        # Remove leetspeak by converting common substitutions to plain text
        leet_map = str.maketrans({'4': 'a', '3': 'e', '1': 'l', '0': 'o', '5': 's', '7': 't', '@': 'a', '$': 's'})
        text = text.translate(leet_map)
        # Escape shell metacharacters
        text = text.replace('`', '').replace('$', '').replace('|', '').replace(';', '').replace('&', '')
        # Limit length to prevent prompt injection
        return text[:500]

        async def call_agent_model(self, user_message: str, file_summary: str) -> str:
        input_text = (
            f"Loan request:\n{user_message or 'No user message provided.'}\n\n"
            f"File summary:\n{file_summary}\n\n"
            "Draft a concise loan processing next-step summary."
        )
        input_hash = hashlib.sha256(input_text.encode()).hexdigest()
        output = await self.model_client.chat(
            model=self.MODEL_NAME,
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {"role": "user", "content": input_text},
            ],
            temperature=0.2,
            max_tokens=250,
        )
        self._audit_log.append({
            "model": self.MODEL_NAME,
            "input_hash": input_hash,
            "output": output,
            "timestamp": time.time(),
            "principal": self.AGENT_ID,
        })
        return output -> str:
        safe_user = self._sanitize_input(user_message or 'No user message provided.')
        safe_summary = self._sanitize_input(file_summary)
        return await self.model_client.chat(
            model=self.MODEL_NAME,
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Loan request:\n{safe_user}\n\n"
                        f"File summary:\n{safe_summary}\n\n"
                        "Draft a concise loan processing next-step summary."
                    ),
                },
            ],
            temperature=0.2,
            max_tokens=250,
        ) -> str:
        sanitized_user = self._sanitize_input(user_message or 'No user message provided.')
        sanitized_summary = self._sanitize_input(file_summary)
        return await self.model_client.chat(
            model=self.MODEL_NAME,
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Loan request:\n{sanitized_user}\n\n"
                        f"File summary:\n{sanitized_summary}\n\n"
                        "Draft a concise loan processing next-step summary."
                    ),
                },
            ],
            temperature=0.2,
            max_tokens=250,
        ) -> str:
        # Sanitize inputs: escape HTML and limit length
        safe_user = html.escape(user_message or 'No user message provided.')[:2000]
        safe_summary = html.escape(file_summary)[:2000]
        return await self.model_client.chat(
            model=self.MODEL_NAME,
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Loan request:\n{safe_user}\n\n"
                        f"File summary:\n{safe_summary}\n\n"
                        "Draft a concise loan processing next-step summary."
                    ),
                },
            ],
            temperature=0.2,
            max_tokens=250,
        ) -> str:
        response = await self.model_client.chat(
            model=self.MODEL_NAME,
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Loan request summary:\n{user_message[:120] if user_message else 'No user message provided.'}\n\n"
                        f"File summary (concise):\n{file_summary[:200] if file_summary else 'No file summary.'}\n\n"
                        "Draft a concise loan processing next-step summary."
                    ),
                },
            ],
            temperature=0.2,
            max_tokens=250,
        )
        self.logger.info(
            "LLM interaction: user_message=%s, file_summary=%s, response=%s",
            user_message,
            file_summary,
            response,
        )
        return response

    def _sanitize_mcp_output(self, output: Any) -> Any:
        """Sanitize MCP server output to prevent injection attacks."""
        if isinstance(output, str):
            import re
            # Remove control characters and limit length
            sanitized = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', output)
            return sanitized[:10000]
        if isinstance(output, dict):
            return {k: self._sanitize_mcp_output(v) for k, v in output.items()}
        if isinstance(output, list):
            return [self._sanitize_mcp_output(item) for item in output]
        return output

    def _sanitize_llm_output(self, output: str) -> None:
        """Raise ValueError if output contains dangerous code execution patterns."""
        dangerous_patterns = ["eval", "exec", "__import__", "compile", "open(", "system(", "popen"]
        for pattern in dangerous_patterns:
            if pattern in output.lower():
                raise ValueError(f"LLM output contains dangerous pattern: {pattern}")

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        user_message = context.get("user_message", "")
        file_contents = context.get("file_contents", [])
        sanitized_contents = _sanitize_file_contents(file_contents)
        file_summary = build_file_summary(sanitized_contents)
        loan_number = extract_reference_number(user_message, prefix="LOAN")

        # Termination criteria: if no loan number is found or user indicates completion, stop early
        if not loan_number or "complete" in user_message.lower():
            return {
                "response": "Agent task complete: no further processing needed.",
                "agent": self.AGENT_NAME,
                "model": self.MODEL_NAME,
                "framework": self.FRAMEWORK_NAME,
                "mcp_activity": [],
            }

        model_output = await self.call_agent_model(user_message, file_summary)
        model_output = (
            "[SYNTHETIC CONTENT - AI-GENERATED]\n"
            f"Provenance: {self.AGENT_NAME} (v{self.VERSION}), Model: {self.MODEL_NAME}\n"
            f"Watermark: LOAN-{loan_number}-{self.AGENT_ID}-{int(asyncio.get_event_loop().time())}\n\n"
            f"{model_output}"
        )
        self._sanitize_llm_output(model_output)

        def sanitize_mcp_input(text: str, max_length: int = 1000) -> str:
            return text.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ')[:max_length]

        safe_user_message = sanitize_mcp_input(user_message)
        safe_file_summary = sanitize_mcp_input(file_summary)

        logging.info("Calling MCP servers: Docx create_document, Excel upsert_row, Email send_email")
                        auth_token = _get_mcp_auth_token()
                async def safe_call_mcp_server(server_name: str, action: str, params: dict) -> Any:
            if server_name not in self.ALLOWED_MCP_SERVERS:
                log_warning(f"MCP server '{server_name}' is not in the allow list. Skipping.")
                return None
            return await call_mcp_server(self.to_dict(), server_name, action, params)

        mcp_activity = await asyncio.gather(
            safe_call_mcp_server(
                "Docx",
                "create_document",
                {
                    "document_title": f"Loan Intake Summary {loan_number}",
                    "document_body": f"User message:\n{user_message}\n\nFile summary:\n{file_summary}",
                },
            ),
            safe_call_mcp_server(
                "Excel",
                "upsert_row",
                {
                    "workbook": "Loan Pipeline",
                    "worksheet": "Applications",
                    "row": {
                        "loan_number": loan_number,
                        "status": "processing",
                        "borrower_request": user_message[:240],
                    },
                },
            ),
            safe_call_mcp_server(
                "Email",
                "send_email",
                {
                    "to": ["borrower@acme.example"],
                    "subject": f"Loan update for {loan_number}",
                    "body": "Your loan request is being reviewed by the Loan Processing Agent.",
                },
            ),
        ),
                "Docx",
                "create_document",
                {
                    "document_title": f"Loan Intake Summary {loan_number}",
                    "document_body": f"User message:\n{user_message}\n\nFile summary:\n{file_summary}",
                },
                auth_token="valid_auth_token",
            ),
                "Docx",
                "create_document",
                {
                    "document_title": f"Loan Intake Summary {loan_number}",
                    "document_body": f"User message:\n{user_message}\n\nFile summary:\n{file_summary}",
                },
                auth_token=auth_token,
            ),
            call_mcp_server(
                self.to_dict(),
                "Excel",
                "upsert_row",
                {
                    "workbook": "Loan Pipeline",
                    "worksheet": "Applications",
                    "row": {
                        "loan_number": loan_number,
                        "status": "processing",
                        "borrower_request": user_message[:240],
                    },
                },
                auth_token=auth_token,
            ),
            call_mcp_server(
                self.to_dict(),
                "Email",
                "send_email",
                {
                    "to": ["borrower@acme.example"],
                    "subject": f"Loan update for {loan_number}",
                    "body": "Your loan request is being reviewed by the Loan Processing Agent.",
                },
                auth_token=auth_token,
            ),
        ),
                "Docx",
                "create_document",
                {
                    "document_title": f"Loan Intake Summary {loan_number}",
                    "document_body": f"User message summary:\n{user_message[:120] if user_message else 'No user message provided.'}\n\nFile summary (concise):\n{file_summary[:200] if file_summary else 'No file summary.'}",
                },
            ),
            call_mcp_server(
                self.to_dict(),
                "Excel",
                "upsert_row",
                {
                    "workbook": "Loan Pipeline",
                    "worksheet": "Applications",
                    "row": {
                        "loan_number": loan_number,
                        "status": "processing",
                        "borrower_request": user_message[:240],
                    },
                },
                auth_token="valid_auth_token",
            ),
            call_mcp_server(
                self.to_dict(),
                "Email",
                "send_email",
                {
                    "to": ["borrower@acme.example"],
                    "subject": f"Loan update for {loan_number}",
                    "body": "Your loan request is being reviewed by the Loan Processing Agent.",
                },
                auth_token="valid_auth_token",
            ),
        )
        mcp_activity = [self._sanitize_mcp_output(r) for r in mcp_activity],
                "Docx",
                "create_document",
                {
                    "document_title": f"Loan Intake Summary {loan_number}",
                    "document_body": f"User message:\n{safe_user_message}\n\nFile summary:\n{safe_file_summary}",
                },
            ),
            call_mcp_server(
                self.to_dict(),
                "Excel",
                "upsert_row",
                {
                    "workbook": "Loan Pipeline",
                    "worksheet": "Applications",
                    "row": {
                        "loan_number": loan_number,
                        "status": "processing",
                        "borrower_request": safe_user_message[:240],
                    },
                },
            ),
            call_mcp_server(
                self.to_dict(),
                "Email",
                "send_email",
                {
                    "to": ["borrower@acme.example"],
                    "subject": f"Loan update for {loan_number}",
                    "body": "Your loan request is being reviewed by the Loan Processing Agent.",
                },
            ),
        )

        response = (
            "This scan-only agent is disconnected from the Orchestrator Agent.\n\n"
            f"Loan reference: {loan_number}\n"
            f"Borrower request reference: {loan_number}\n\n"
            f"Loan summary:\n{model_output}"
        )

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "mcp_activity": mcp_activity,
        }


def _sanitize_file_contents(contents: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Remove or neutralize file content that may contain hidden prompts, base64, or malicious instructions."""
    sanitized = []
    for item in contents:
        text = item.get("text", "")
        if not text:
            sanitized.append(item)
            continue
        # Detect base64-encoded strings (long alphanumeric sequences with padding)
        if re.search(r'[A-Za-z0-9+/]{40,}={0,2}', text):
            # Remove base64-like tokens
            text = re.sub(r'[A-Za-z0-9+/]{40,}={0,2}', '[REDACTED]', text)
        # Detect common prompt injection patterns (e.g., "ignore previous instructions", "system prompt")
        injection_patterns = [
            r'ignore\s+(all\s+)?previous\s+(instructions|commands|prompts)',
            r'disregard\s+(all\s+)?previous',
            r'you\s+are\s+(now|not\s+required\s+to)',
            r'new\s+instructions?\s*:',
            r'override\s+(system|prompt)',
            r'pretend\s+(you\s+are|to\s+be)',
            r'act\s+as\s+if',
            r'from\s+now\s+on',
        ]
        for pattern in injection_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                text = re.sub(pattern, '[REDACTED]', text, flags=re.IGNORECASE)
        # Rebuild item with sanitized text
        sanitized_item = {k: v for k, v in item.items() if k != 'text'}
        sanitized_item['text'] = text
        sanitized.append(sanitized_item)
    return sanitized_contents

loan_processing_agent = LoanProcessingAgent()
