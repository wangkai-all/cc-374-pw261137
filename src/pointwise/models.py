"""Domain model: loaded rows, validation findings, dependency chains.

The pipeline never silently deletes a row. Every row carries an intrinsic
validation verdict and, when excluded, a finding that names the reason and
the dependency path that caused it.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

TABLES = ("accounts", "relationships", "transactions")


class Stage(str, Enum):
    """Pipeline stages. State is persisted so a crash at any stage is resumable."""

    RECEIVED = "RECEIVED"          # batch files received and checksummed
    VALIDATING = "VALIDATING"      # validator running
    VALIDATED = "VALIDATED"        # validation done; nothing published yet
    PUBLISHING = "PUBLISHING"      # publish directory being assembled
    PUBLISHED = "PUBLISHED"        # release directory atomically committed
    CRASHED_PRE_PUBLISH = "CRASHED_PRE_PUBLISH"   # simulated crash after validate, before publish
    CRASHED_DURING_PUBLISH = "CRASHED_DURING_PUBLISH"


class Policy(str, Enum):
    REJECT_BATCH = "reject_batch"          # whole batch rejected, nothing published
    RETAIN_CLEAN_SUBSET = "retain_subset"  # keep only the referentially closed subset


class Severity(str, Enum):
    ERROR = "ERROR"
    TAINT = "TAINT"   # row intrinsically fine, but reachable from a broken dependency


# Human-readable remediation catalog. The handback manifest must explain how to
# fix and re-ingest every quarantined row, so each code has one canonical text.
ERROR_CATALOG: dict[str, str] = {
    "E_KEY_MISSING": "Primary key is blank. Assign a stable key and re-ingest.",
    "E_KEY_DUPLICATE": "Duplicate primary key in batch. Keep one authoritative row, remove or re-key the other, then re-ingest.",
    "E_FIELD_REQUIRED": "A required field is blank. Fill it from the source system and re-ingest.",
    "E_NUMBER_FORMAT": "Numeric field is not a valid number. Correct the value at source and re-ingest.",
    "E_BALANCE_NEGATIVE": "Balance is negative. Post correcting entries in the ledger so the account balance is non-negative, then re-ingest.",
    "E_STRENGTH_RANGE": "Relationship strength must be between 0 and 1 inclusive. Recompute the score and re-ingest.",
    "E_AMOUNT_NONPOSITIVE": "Transaction amount must be strictly positive. Reverse and re-book the transaction correctly, then re-ingest.",
    "E_ENUM": "Field value is outside the allowed enum. Map it to a permitted value in the source extract and re-ingest.",
    "E_FK_MISSING": "Referenced key does not exist in the batch. Either supply the referenced row or remove/reroute this reference, then re-ingest.",
    "E_TAINTED": "Row itself is well-formed but depends on a quarantined row. Fix the root cause named in the dependency path; this row is then re-validated automatically.",
}

ALLOWED_STATUS = {"ACTIVE", "SUSPENDED", "CLOSED"}
ALLOWED_RELATION = {"PAYER", "OWNER", "EMPLOYER", "DIRECTOR", "FRIEND"}
ALLOWED_CURRENCY = {"USD", "EUR", "GBP"}


def canonical_hash(table: str, values: dict[str, str]) -> str:
    """Content hash of a row's materialized values (key included)."""
    joined = table + "|" + "|".join(f"{k}={values.get(k, '')}" for k in sorted(values))
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()[:16]


@dataclass
class Row:
    table: str
    line_no: int                       # 1-based line in the source CSV (excluding header)
    key: str                           # primary key value, "" when missing
    values: dict[str, str]
    content_hash: str = ""
    # filled by the validator
    intrinsic_errors: list["Finding"] = field(default_factory=list)
    taint_path: Optional[list["ChainLink"]] = None   # set when excluded by dependency
    status: str = "UNSEEN"             # UNSEEN | VALID | QUARANTINED
    quarantined_in_version: Optional[int] = None

    def __post_init__(self) -> None:
        if not self.content_hash:
            self.content_hash = canonical_hash(self.table, self.values)

    @property
    def is_intrinsically_bad(self) -> bool:
        return bool(self.intrinsic_errors)

    @property
    def ref(self) -> str:
        return f"{self.table}:{self.key or '<missing-key>'}#L{self.line_no}"


@dataclass
class ChainLink:
    """One hop in a dependency propagation chain."""
    table: str
    key: str
    line_no: int
    role: str          # ROOT (the bad row) or VIA (a row that referenced it)
    edge: str = ""     # human-readable description of the reference edge

    def to_dict(self) -> dict:
        return {"table": self.table, "key": self.key, "line_no": self.line_no,
                "role": self.role, "edge": self.edge}


@dataclass
class Finding:
    code: str
    message: str
    severity: Severity
    table: str
    key: str
    line_no: int
    chain: list[ChainLink] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "code": self.code,
            "message": self.message,
            "severity": self.severity.value,
            "table": self.table,
            "key": self.key,
            "line_no": self.line_no,
            "chain": [c.to_dict() for c in self.chain],
            "remediation": ERROR_CATALOG.get(self.code, ""),
        }
