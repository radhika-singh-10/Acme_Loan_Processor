"""Mock borrower database seeded from the HP employee details demo PDF."""

from copy import deepcopy
from typing import Any


SEED_SOURCE_DOCUMENT = "demo_pdfs/pii_hp_employee_details.pdf"

_MOCK_BORROWER_RECORDS: list[dict[str, Any]] = [
    {
        "name": "Alice Morgan",
        "employee_id": "EMP001",
        "date_of_birth": "1985-02-14",
        "ssn": "421-55-1023",
        "address": "123 Oak Street, Portland, OR 97205",
        "loan_status": "Under review",
        "loan_type": "Home equity loan",
        "loan_balance": 184250,
    },
    {
        "name": "Brian Keller",
        "employee_id": "EMP002",
        "date_of_birth": "1990-07-09",
        "ssn": "512-44-8831",
        "address": "88 Pine Avenue, Beaverton, OR 97005",
        "loan_status": "Conditional approval",
        "loan_type": "Auto refinance",
        "loan_balance": 26840,
        "credit_score": 706,
    },
    {
        "name": "Carla Nguyen",
        "employee_id": "EMP003",
        "date_of_birth": "1988-11-22",
        "ssn": "633-29-4410",
        "address": "451 Maple Drive, Hillsboro, OR 97123",
        "loan_status": "Pending employment verification",
        "loan_type": "Personal loan",
        "loan_balance": 12450,
    },
    {
        "name": "Daniel Ruiz",
        "employee_id": "EMP004",
        "date_of_birth": "1979-04-03",
        "ssn": "298-61-7742",
        "address": "900 Cedar Lane, Eugene, OR 97401",
        "loan_status": "Documentation gap",
        "loan_type": "Mortgage refinance",
        "loan_balance": 342100,
        "credit_score": 682,
    },
]

_MOCK_SUPPORT_CASES: list[dict[str, Any]] = [
    {
        "case_number": "CASE-240217",
        "borrower_name": "Alice Morgan",
        "employee_id": "EMP001",
        "topic": "Borrower portal update request",
        "status": "Pending documentation review",
        "owner_team": "Borrower Care",
    },
    {
        "case_number": "CASE-240318",
        "borrower_name": "Brian Keller",
        "employee_id": "EMP002",
        "topic": "Loan status callback request",
        "status": "Waiting on support follow-up",
        "owner_team": "Loan Operations",
    },
    {
        "case_number": "CASE-240412",
        "borrower_name": "Carla Nguyen",
        "employee_id": "EMP003",
        "topic": "Escalated servicing question",
        "status": "Escalated to servicing team",
        "owner_team": "Servicing Support",
    },
]


def strip_pii_fields(record: dict[str, Any]) -> dict[str, Any]:
    """Remove PII fields from a borrower record before returning to the AI model."""
    borrower = deepcopy(record)
    for field in ("ssn", "address", "date_of_birth", "employee_id"):
        borrower.pop(field, None)
    return borrower


def search_borrower_records(query: str) -> list[dict[str, Any]]:
    text = (query or "").lower()
    searchable_tokens = [
        token for token in text.replace(",", " ").split()
        if len(token) > 2 and token not in {"the", "for", "and", "with", "show", "run", "loan", "status", "check"}
    ]
    matches = []
    for record in _MOCK_BORROWER_RECORDS:
        haystack = " ".join(
            [
                record["name"],
                record["employee_id"],
                record["address"],
                record["loan_status"],
                record["loan_type"],
            ]
        ).lower()
        if not text or record["name"].lower() in text or record["employee_id"].lower() in text:
            matches.append(strip_pii_fields(ensure_credit_score(record)))
            continue
        if searchable_tokens and all(token in haystack for token in searchable_tokens):
            matches.append(strip_pii_fields(ensure_credit_score(record)))
    return matches or [strip_pii_fields(ensure_credit_score(_MOCK_BORROWER_RECORDS[0]))]


def ensure_credit_score(record: dict[str, Any]) -> dict[str, Any]:
    borrower = deepcopy(record)
    if "credit_score" not in borrower:
        deterministic_seed = sum(ord(char) for char in borrower["employee_id"])
        borrower["credit_score"] = 640 + (deterministic_seed % 91)
    return borrower


def search_support_cases(query: str) -> list[dict[str, Any]]:
    text = (query or "").lower()
    searchable_tokens = [
        token for token in text.replace(",", " ").split()
        if len(token) > 2 and token not in {"the", "for", "and", "with", "case", "support", "borrower", "update", "status"}
    ]
    matches = []
    for record in _MOCK_SUPPORT_CASES:
        haystack = " ".join(
            [
                record["case_number"],
                record["borrower_name"],
                record["employee_id"],
                record["topic"],
                record["status"],
                record["owner_team"],
            ]
        ).lower()
        if record["case_number"].lower() in text or record["borrower_name"].lower() in text:
            matches.append(deepcopy(record))
            continue
        if searchable_tokens and all(token in haystack for token in searchable_tokens):
            matches.append(deepcopy(record))

    return matches or [deepcopy(_MOCK_SUPPORT_CASES[0])]


def format_borrower_record(record: dict[str, Any]) -> str:
    """
    Format a borrower record for display, with PII fields masked to prevent exposure on the UI or to the AI model.
    """
    ssn = record.get("ssn", "")
    masked_ssn = "***-**-" + ssn[-4:] if ssn and len(ssn) >= 4 else "***-**-****"

    address = record.get("address", "")
    masked_address = "****" if address else "****"

    dob = record.get("date_of_birth", "")
    masked_dob = "****-**-**" if dob else "****-**-**"

    employee_id = record.get("employee_id", "")
    masked_employee_id = "EMP***" if employee_id else "EMP***"

    return (
        f"Name: {record['name']}\n"
        f"Employee ID: {masked_employee_id}\n"
        f"Date of Birth: {masked_dob}\n"
        f"SSN: {masked_ssn}\n"
        f"Address: {masked_address}\n"
        f"Loan Type: {record['loan_type']}\n"
        f"Loan Status: {record['loan_status']}\n"
        f"Loan Balance: ${record['loan_balance']:,}\n"
        f"Credit Score: {record['credit_score']}"
    )