"""Validator.

Two layers, kept explicitly separate:

1. Intrinsic, field-level validation of each row. Pure results are cached by
   content hash so a pointwise fix only re-validates what changed. Graph-level
   checks (duplicate keys, foreign keys) are NEVER cached: they depend on the
   whole batch and must be recomputed on every validation.
2. Taint fixpoint over the reference graph. A well-formed row that references
   a quarantined row is itself quarantined, carrying the full dependency chain
   so no row is ever removed without a documented reason.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Optional

from .loader import LoadedBatch, PRIMARY_KEY
from .models import (
    ALLOWED_CURRENCY, ALLOWED_RELATION, ALLOWED_STATUS, ChainLink, Finding,
    Row, Severity, TABLES,
)


@dataclass
class MissingRef:
    table: str
    key: str
    line_no: int
    field: str
    missing_value: str

    def to_dict(self) -> dict:
        return {"table": self.table, "key": self.key, "line_no": self.line_no,
                "field": self.field, "missing_value": self.missing_value}


@dataclass
class ValidationResult:
    rows: dict[str, list[Row]]
    findings: list[Finding]
    missing_refs: list[MissingRef]
    stats: dict
    # content hashes whose intrinsic verdict was served from the cache
    cache_hits: set[str] = field(default_factory=set)
    cache_misses: set[str] = field(default_factory=set)

    def row_by_ref(self, table: str, key: str) -> Optional[Row]:
        for r in self.rows[table]:
            if r.key == key:
                return r
        return None

    def to_summary(self) -> dict:
        return {
            "stats": self.stats,
            "missing_refs": [m.to_dict() for m in self.missing_refs],
            "findings": [f.to_dict() for f in self.findings],
        }


class IntrinsicCache:
    """Maps row content hash -> list of field-level findings (dicts)."""

    def __init__(self, backing: Optional[dict] = None) -> None:
        self._mem: dict[str, list[dict]] = backing or {}

    def get(self, content_hash: str) -> Optional[list[dict]]:
        return self._mem.get(content_hash)

    def put(self, content_hash: str, findings: list[Finding]) -> None:
        self._mem[content_hash] = [
            {"code": f.code, "message": f.message, "severity": f.severity.value}
            for f in findings
        ]

    def as_dict(self) -> dict:
        return dict(self._mem)


def _parse_float(value: str) -> Optional[float]:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _field_intrinsic(row: Row) -> list[Finding]:
    """Pure field-level checks. No cross-row logic here (see module docstring)."""
    out: list[Finding] = []
    v = row.values

    def add(code: str, message: str) -> None:
        out.append(Finding(code=code, message=message, severity=Severity.ERROR,
                           table=row.table, key=row.key, line_no=row.line_no))

    if not row.key:
        add("E_KEY_MISSING", f"{PRIMARY_KEY[row.table]} is empty")

    if row.table == "accounts":
        if not v.get("account_holder"):
            add("E_FIELD_REQUIRED", "account_holder is empty")
        cur = v.get("currency", "")
        if not cur:
            add("E_FIELD_REQUIRED", "currency is empty")
        elif cur not in ALLOWED_CURRENCY:
            add("E_ENUM", f"currency '{cur}' not in {sorted(ALLOWED_CURRENCY)}")
        bal_raw = v.get("balance", "")
        if not bal_raw:
            add("E_FIELD_REQUIRED", "balance is empty")
        else:
            bal = _parse_float(bal_raw)
            if bal is None:
                add("E_NUMBER_FORMAT", f"balance '{bal_raw}' is not numeric")
            elif bal < 0:
                add("E_BALANCE_NEGATIVE", f"balance {bal} is negative")
        status = v.get("status", "")
        if status not in ALLOWED_STATUS:
            add("E_ENUM", f"status '{status}' not in {sorted(ALLOWED_STATUS)}")
        if not v.get("country"):
            add("E_FIELD_REQUIRED", "country is empty")

    elif row.table == "relationships":
        for col in ("source_account_id", "target_account_id"):
            if not v.get(col):
                add("E_FIELD_REQUIRED", f"{col} is empty")
        rel = v.get("relation_type", "")
        if rel not in ALLOWED_RELATION:
            add("E_ENUM", f"relation_type '{rel}' not in {sorted(ALLOWED_RELATION)}")
        s_raw = v.get("strength", "")
        if not s_raw:
            add("E_FIELD_REQUIRED", "strength is empty")
        else:
            strength = _parse_float(s_raw)
            if strength is None:
                add("E_NUMBER_FORMAT", f"strength '{s_raw}' is not numeric")
            elif not 0.0 <= strength <= 1.0:
                add("E_STRENGTH_RANGE", f"strength {strength} outside [0, 1]")

    elif row.table == "transactions":
        for col in ("from_account_id", "to_account_id", "currency"):
            if not v.get(col):
                add("E_FIELD_REQUIRED", f"{col} is empty")
        cur = v.get("currency", "")
        if cur and cur not in ALLOWED_CURRENCY:
            add("E_ENUM", f"currency '{cur}' not in {sorted(ALLOWED_CURRENCY)}")
        amt_raw = v.get("amount", "")
        if not amt_raw:
            add("E_FIELD_REQUIRED", "amount is empty")
        else:
            amt = _parse_float(amt_raw)
            if amt is None:
                add("E_NUMBER_FORMAT", f"amount '{amt_raw}' is not numeric")
            elif amt <= 0:
                add("E_AMOUNT_NONPOSITIVE", f"amount {amt} must be strictly positive")

    return out


# (table, column) reference declarations; optional columns only error when present
REF_EDGES = {
    "relationships": [("source_account_id", "accounts", False),
                      ("target_account_id", "accounts", False)],
    "transactions": [("from_account_id", "accounts", False),
                     ("to_account_id", "accounts", False),
                     ("via_relationship_id", "relationships", True)],
}


class Validator:
    def __init__(self, cache: Optional[IntrinsicCache] = None) -> None:
        self.cache = cache or IntrinsicCache()

    def validate(self, loaded: LoadedBatch) -> ValidationResult:
        rows = loaded.rows
        findings: list[Finding] = []
        missing: list[MissingRef] = []
        cache_hits: set[str] = set()
        cache_misses: set[str] = set()

        # ---- layer 1a: cached field-level intrinsic validation --------------
        for row in loaded.all_rows():
            cached = self.cache.get(row.content_hash)
            if cached is not None:
                row.intrinsic_errors = [
                    Finding(code=c["code"], message=c["message"],
                            severity=Severity(c["severity"]), table=row.table,
                            key=row.key, line_no=row.line_no)
                    for c in cached
                ]
                cache_hits.add(row.content_hash)
            else:
                row.intrinsic_errors = _field_intrinsic(row)
                self.cache.put(row.content_hash, row.intrinsic_errors)
                cache_misses.add(row.content_hash)
            findings.extend(row.intrinsic_errors)

        # ---- layer 1b: graph-level checks, always recomputed ----------------
        key_sets: dict[str, set[str]] = {t: set() for t in TABLES}
        key_owners: dict[tuple[str, str], list[Row]] = {(t, k): [] for t in TABLES for k in []}
        key_owners = {}
        for table in TABLES:
            for row in rows[table]:
                if row.key:
                    key_sets[table].add(row.key)
                    key_owners.setdefault((table, row.key), []).append(row)

        # duplicate primary keys: every sharing row is quarantined
        for (table, key), owners in key_owners.items():
            if key and len(owners) > 1:
                for row in owners:
                    f = Finding(code="E_KEY_DUPLICATE",
                                message=f"duplicate {PRIMARY_KEY[table]} '{key}' "
                                        f"appears on lines "
                                        f"{sorted(r.line_no for r in owners)}",
                                severity=Severity.ERROR, table=table, key=key,
                                line_no=row.line_no)
                    row.intrinsic_errors.append(f)
                    findings.append(f)

        # foreign keys: missing references are direct errors on the referencing row
        # present edges (target exists) become propagation edges for the taint fixpoint
        reverse_edges: dict[str, list[tuple[Row, str]]] = {}
        # reverse_edges[target_ref] -> list[(dependent_row, edge_label)]
        for table, edges in REF_EDGES.items():
            for row in rows[table]:
                for col, target_table, optional in edges:
                    val = row.values.get(col, "")
                    if not val:
                        continue
                    if val not in key_sets[target_table]:
                        f = Finding(
                            code="E_FK_MISSING",
                            message=f"{col}='{val}' has no matching "
                                    f"{PRIMARY_KEY[target_table]} in {target_table}",
                            severity=Severity.ERROR, table=table, key=row.key,
                            line_no=row.line_no)
                        row.intrinsic_errors.append(f)
                        findings.append(f)
                        missing.append(MissingRef(table, row.key, row.line_no, col, val))
                    else:
                        label = f"{row.table}.{col} -> {target_table}:{val}"
                        reverse_edges.setdefault(f"{target_table}:{val}", []).append((row, label))

        # ---- layer 2: taint fixpoint (BFS over reverse dependency edges) ----
        bad_refs = {r.ref for r in loaded.all_rows() if r.is_intrinsically_bad}
        queue: deque[tuple[Row, list[ChainLink]]] = deque()
        for row in loaded.all_rows():
            if row.is_intrinsically_bad:
                queue.append((row, [ChainLink(row.table, row.key, row.line_no, "ROOT", "")]))

        tainted: dict[str, list[ChainLink]] = {}
        while queue:
            parent, parent_chain = queue.popleft()
            for dependent, label in reverse_edges.get(f"{parent.table}:{parent.key}", []):
                if dependent.is_intrinsically_bad or dependent.ref in tainted:
                    continue
                chain = parent_chain + [ChainLink(dependent.table, dependent.key,
                                                  dependent.line_no, "VIA", label)]
                tainted[dependent.ref] = chain
                queue.append((dependent, chain))

        for row in loaded.all_rows():
            if row.is_intrinsically_bad:
                row.status = "QUARANTINED"
            elif row.ref in tainted:
                row.status = "QUARANTINED"
                row.taint_path = tainted[row.ref]
                root = row.taint_path[0]
                f = Finding(
                    code="E_TAINTED",
                    message=f"depends on quarantined {root.table}:{root.key or '<missing-key>'}",
                    severity=Severity.TAINT, table=row.table, key=row.key,
                    line_no=row.line_no, chain=list(row.taint_path))
                findings.append(f)
            else:
                row.status = "VALID"

        stats = self._stats(rows, findings, missing)
        return ValidationResult(rows=rows, findings=findings, missing_refs=missing,
                                stats=stats, cache_hits=cache_hits, cache_misses=cache_misses)

    @staticmethod
    def _stats(rows: dict[str, list[Row]], findings: list[Finding],
               missing: list[MissingRef]) -> dict:
        per_table = {}
        for table in TABLES:
            tr = rows[table]
            per_table[table] = {
                "total": len(tr),
                "valid": sum(1 for r in tr if r.status == "VALID"),
                "quarantined": sum(1 for r in tr if r.status == "QUARANTINED"),
                "intrinsic_bad": sum(1 for r in tr if r.is_intrinsically_bad),
                "tainted": sum(1 for r in tr if r.taint_path is not None),
            }
        return {
            "per_table": per_table,
            "total_rows": sum(len(t) for t in rows.values()),
            "error_findings": sum(1 for f in findings if f.severity == Severity.ERROR),
            "taint_findings": sum(1 for f in findings if f.severity == Severity.TAINT),
            "missing_references": len(missing),
        }
