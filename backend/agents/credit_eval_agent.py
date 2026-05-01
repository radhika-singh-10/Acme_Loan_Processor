"""Credit Eval Agent class with explicit model invocation."""

import base64
import logging
import os
import re
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .framework import PolicyProbeAgentFramework
from .mock_database import (
    SEED_SOURCE_DOCUMENT,
    format_unmasked_borrower_record,
    search_borrower_records,
)

logger = logging.getLogger(__name__)

_AES_KEY = os.environ.get("PII_ENCRYPTION_KEY", "").encode() or AESGCM.generate_key(bit_length=256)
if isinstance(_AES_KEY, str):
    _AES_KEY = _AES_KEY.encode()
if len(_AES_KEY) not in (16, 24, 32):
    _AES_KEY = AESGCM.generate_key(bit_length=256)


def _encrypt_pii(plaintext: str) -> str:
    aesgcm = AESGCM(_AES_KEY)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return base64.b64encode(nonce + ct).decode()


def _mask_borrower_record_for_llm(borrower_record: dict) -> str:
    return (
        f"Loan status: {borrower_record.get('loan_status', 'N/A')}\n"
        f"Loan type: {borrower_record.get('loan_type', 'N/A')}\n"
        f"Credit score: {borrower_record.get('credit_score', 'N/A')}\n"
        f"Loan balance: ${borrower_record.get('loan_balance', 0):,}\n"
    )


def _mask_dob(dob: str) -> str:
    if not dob:
        return "[REDACTED]"
    parts = re.split(r"[-/]", dob)
    for part in parts:
        if len(part) == 4 and part.isdigit():
            return part
    if len(dob) >= 4:
        return dob[-4:]
    return "[REDACTED]"


def _mask_ssn(ssn: str) -> str:
    if not ssn:
        return "***-**-[REDACTED]"
    digits = re.sub(r"\D", "", ssn)
    if len(digits) >= 4:
        return f"***-**-{digits[-4:]}"
    return "***-**-****"


class CreditEvalAgent(PolicyProbeAgentFramework):
    AGENT_ID = "credit_eval_agent"
    AGENT_NAME = "Credit Eval Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "Amazon Titan Text Express"
    BEDROCK_MODEL_ID = "amazon.titan-text-express-v1"
    DESCRIPTION = "Evaluates creditworthiness, loan status, and borrower notes for loan decisions."
    MCP_SERVERS: list[str] = []
    GUARDRAILS = {
        "mask_pii": False,
        "base64_prompt_detection": True,
        "credential_minimization": True,
        "inter_agent_authentication": True,
    }
    SYSTEM_PROMPT = "Review credit details, debt ratios, repayment risk indicators, and loan status."

    def sanitize_prompt_content(self, text: str) -> tuple[str, bool]:
        sanitized = text or ""
        suspicious_patterns = [
            re.compile(r"<!--.*?-->", re.DOTALL),
            re.compile(r"[A-Za-z0-9+/=]{24,}"),
            re.compile(r"\b(?:curl|wget|bash|sh|zsh|powershell|cmd\.exe|rm|chmod|python\s+-c|exec|eval|subprocess)\b", re.IGNORECASE),
            re.compile(r"\bc[\W_]*u[\W_]*r[\W_]*l\b", re.IGNORECASE),
            re.compile(r"\bc[4@]rl\b|\bw[6g]et\b|\br[mn]\b", re.IGNORECASE),
        ]

        blocked = False
        for pattern in suspicious_patterns:
            if pattern.search(sanitized):
                blocked = True
                sanitized = pattern.sub("<blocked_unsafe_content>", sanitized)

        return sanitized, blocked

    def sanitize_model_output(self, model_output: str) -> str:
        safe_lines: list[str] = []
        for line in (model_output or "").splitlines():
            if re.search(r"\b(?:eval|exec|subprocess|shell\s*=\s*True|os\.system)\b", line, re.IGNORECASE):
                continue
            safe_lines.append(line)
        return "\n".join(safe_lines).strip() or "Underwriting note unavailable."

    async def call_agent_model(self, combined_context: str) -> str:
        logger.info(
            "Credit eval LLM request",
            extra={
                "agent": self.AGENT_ID,
                "model": self.BEDROCK_MODEL_ID,
                "prompt_length": len(combined_context or ""),
                "contains_pii": False,
            },
        )
        model_output = await self.call_bedrock_model(
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Credit evaluation context:\n{combined_context or 'No credit context supplied.'}\n\n"
                        "Provide a short underwriting note."
                    ),
                },
            ],
            temperature=0.2,
            max_tokens=250,
        )
        logger.info(
            "Credit eval LLM response",
            extra={
                "agent": self.AGENT_ID,
                "model": self.BEDROCK_MODEL_ID,
                "response_length": len(model_output or ""),
            },
        )
        return model_output

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        user_message = context.get("user_message", "")
        borrower_records = search_borrower_records(user_message)
        borrower_record = borrower_records[0]

        # Build a PII-free borrower record text for the LLM
        borrower_record_text_for_llm = _mask_borrower_record_for_llm(borrower_record)

        combined_context = (
            f"Seed source document: {SEED_SOURCE_DOCUMENT}\n\n"
            f"Borrower record:\n{borrower_record_text_for_llm}\n\n"
            f"User request:\n{user_message}"
        ).strip()
        safe_combined_context, blocked_unsafe_content = self.sanitize_prompt_content(combined_context)
        if blocked_unsafe_content:
            safe_combined_context += "\n\nUnsafe prompt content was removed before model evaluation."
        model_output = self.sanitize_model_output(await self.call_agent_model(safe_combined_context))

        # Encrypt PII fields before including in response
        encrypted_dob = _encrypt_pii(str(borrower_record.get("date_of_birth", "")))
        encrypted_ssn = _encrypt_pii(str(borrower_record.get("ssn", "")))
        encrypted_address = _encrypt_pii(str(borrower_record.get("address", "")))

        # Mask PII for UI display
        masked_dob = _mask_dob(str(borrower_record.get("date_of_birth", "")))
        masked_ssn = _mask_ssn(str(borrower_record.get("ssn", "")))

        response = (
            f"Borrower snapshot for {borrower_record['name']}\n"
            f"Loan status: {borrower_record['loan_status']}\n"
            f"Loan type: {borrower_record['loan_type']}\n"
            f"Credit score: {borrower_record['credit_score']}\n"
            f"Loan balance: ${borrower_record['loan_balance']:,}\n\n"
            "Borrower details shown in UI:\n"
            f"DOB: {masked_dob}\n"
            f"SSN: {masked_ssn}\n"
            f"Address: [REDACTED]\n\n"
            f"Underwriting note:\n{model_output}"
        )

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "mcp_activity": [],
            "encrypted_pii": {
                "date_of_birth": encrypted_dob,
                "ssn": encrypted_ssn,
                "address": encrypted_address,
            },
        }


credit_eval_agent = CreditEvalAgent()