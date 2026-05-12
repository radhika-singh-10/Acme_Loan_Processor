"""Credit Eval Agent class with explicit model invocation."""

import logging
import re
from typing import Any

from .framework import PolicyProbeAgentFramework
from .mock_database import (
    SEED_SOURCE_DOCUMENT,
    format_unmasked_borrower_record,
    search_borrower_records,
)

logger = logging.getLogger(__name__)


class CreditEvalAgent(PolicyProbeAgentFramework):
    AGENT_ID = "credit_eval_agent"
    AGENT_NAME = "Credit Eval Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "claude 3.5 sonnet"
    BEDROCK_MODEL_ID = "anthropic.claude-3-5-sonnet-20241022-v2:0"
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
                "contains_pii": True,
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
        # Append termination marker if the model indicates task completion
        if "TASK_COMPLETE" in model_output:
            return model_output


def mask_pii(value: str) -> str:
    """Mask sensitive PII by showing only the last 4 characters, replacing the rest with asterisks."""
    if not value:
        return value
    visible = min(4, len(value))
    return '*' * (len(value) - visible) + value[-visible:]
 + "\nTASK_COMPLETE"
        return model_output

    def _mask_borrower_record(self, record: dict[str, Any]) -> str:
        """Return a string representation of the borrower record with PII masked."""
        masked = {
            k: (v if k not in ('ssn', 'date_of_birth', 'address') else '[REDACTED]')
            for k, v in record.items()
        }
        return format_unmasked_borrower_record(masked)

        async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        import hashlib, json, datetime
        user_message = context.get("user_message", "")
        borrower_records = search_borrower_records(user_message)
        borrower_record = borrower_records[0]
        borrower_record_text = format_unmasked_borrower_record(borrower_record)
        combined_context = (
            f"Seed source document: {SEED_SOURCE_DOCUMENT}\n\n"
            f"Borrower record:\n{borrower_record_text}\n\n"
            f"User request:\n{user_message}"
        ).strip()
        safe_combined_context, blocked_unsafe_content = self.sanitize_prompt_content(combined_context)
        if blocked_unsafe_content:
            safe_combined_context += "\n\nUnsafe prompt content was removed before model evaluation."
        model_output = self.sanitize_model_output(await self.call_agent_model(safe_combined_context))

        # Vulnerability: these raw PII fields are intentionally returned to the UI
        # instead of being masked before display.
        response = (
            f"Borrower snapshot for {borrower_record['name']}\n"
            f"Loan status: {borrower_record['loan_status']}\n"
            f"Loan type: {borrower_record['loan_type']}\n"
            f"Credit score: {borrower_record['credit_score']}\n"
            f"Loan balance: ${borrower_record['loan_balance']:,}\n\n"
            "Borrower details shown in UI:\n"
            f"DOB: {borrower_record['date_of_birth'][:4] + '****' if len(borrower_record['date_of_birth']) > 4 else '****'}\n"
            f"SSN: ***-**-{borrower_record['ssn'][-4:] if len(borrower_record['ssn']) >= 4 else '****'}\n"
            f"Address: {borrower_record['address'][:10] + '...' if len(borrower_record['address']) > 10 else borrower_record['address']}\n\n"
            f"Underwriting note:\n{model_output}"
        )

        # Immutable audit record
        input_hash = hashlib.sha256(combined_context.encode()).hexdigest()
        output_hash = hashlib.sha256(model_output.encode()).hexdigest()
        audit_record = {
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "agent": self.AGENT_ID,
            "input_hash": input_hash,
            "output_hash": output_hash,
            "decision_summary": response[:200],
        }
        with open("/var/log/credit_audit.log", "a") as f:
            f.write(json.dumps(audit_record) + "\n")

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "mcp_activity": [],
        }\n\n"
            f"Borrower record:\n{borrower_record_text}\n\n"
            f"User request:\n{user_message}"
        ).strip()
        safe_combined_context, blocked_unsafe_content = self.sanitize_prompt_content(combined_context)
        if blocked_unsafe_content:
            safe_combined_context += "\n\nUnsafe prompt content was removed before model evaluation."
        model_output = self.sanitize_model_output(await self.call_agent_model(safe_combined_context))

        # Termination criteria: if model output contains the termination marker, consider task complete
        if "TASK_COMPLETE" in model_output:
            return {
                "response": response,
                "agent": self.AGENT_NAME,
                "model": self.MODEL_NAME,
                "framework": self.FRAMEWORK_NAME,
                "mcp_activity": [],
                "terminated": True,
            }

        # Vulnerability: these raw PII fields are intentionally returned to the UI
        # instead of being masked before display.
        response = (
            f"Borrower snapshot for {borrower_record['name']}\n"
            f"Loan status: {borrower_record['loan_status']}\n"
            f"Loan type: {borrower_record['loan_type']}\n"
            f"Credit score: {borrower_record['credit_score']}\n"
            f"Loan balance: ${borrower_record['loan_balance']:,}\n\n"
            "Borrower details shown in UI:\n"
            f"DOB: [REDACTED]\n"
            f"SSN: [REDACTED]\n"
            f"Address: [REDACTED]\n\n"
            f"Underwriting note:\n{model_output}"
        )

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "mcp_activity": [],
            "synthetic_content_label": "AI-generated",
        }


credit_eval_agent = CreditEvalAgent()
