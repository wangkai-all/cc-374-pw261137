"""Quarantine policy.

Two acceptable outcomes for a batch containing bad rows; neither one silently
drops dependencies:

* REJECT_BATCH       - nothing is published. Every row lands in the quarantine
                       set with its reason, and the handback manifest explains
                       how to repair and re-ingest the whole batch.
* RETAIN_CLEAN_SUBSET - publish the rows marked VALID. Because taint propagation
                       already excluded every row reachable from a bad one, the
                       published subset is referentially closed: no published
                       row references anything outside the subset.

The closure invariant is re-checked here rather than assumed.
"""
from __future__ import annotations

from dataclasses import dataclass

from .models import Policy, Row, TABLES
from .validator import REF_EDGES, ValidationResult


@dataclass
class PolicyDecision:
    policy: Policy
    published: dict[str, list[Row]]
    quarantined: dict[str, list[Row]]
    deleted_dependencies: list[str]   # human-readable list of what was removed and why
    closure_violations: list[str]     # must be empty for a publishable subset


def _closure_violations(published: dict[str, list[Row]]) -> list[str]:
    """No published row may reference a key absent from the published tables."""
    published_sets = {t: {r.key for r in published[t] if r.key} for t in TABLES}
    violations: list[str] = []
    for table, edges in REF_EDGES.items():
        for row in published[table]:
            for col, target_table, optional in edges:
                val = row.values.get(col, "")
                if not val:
                    continue
                if val not in published_sets[target_table]:
                    violations.append(
                        f"{row.ref} references {target_table}:{val} via {col}, "
                        f"which is not in the published subset (orphan reference)")
    return violations


def apply_policy(result: ValidationResult, policy: Policy) -> PolicyDecision:
    published: dict[str, list[Row]] = {t: [] for t in TABLES}
    quarantined: dict[str, list[Row]] = {t: [] for t in TABLES}

    for table in TABLES:
        for row in result.rows[table]:
            if row.status == "VALID":
                published[table].append(row)
            else:
                quarantined[table].append(row)

    removed: list[str] = []
    for table in TABLES:
        for row in quarantined[table]:
            if row.taint_path:
                root = row.taint_path[0]
                reason = (f"TAINT via chain "
                          + " -> ".join(f"{c.table}:{c.key or '<missing-key>'}"
                                        for c in row.taint_path)
                          + f"; root cause at {root.table} line {root.line_no}")
            else:
                codes = ", ".join(sorted({f.code for f in row.intrinsic_errors}))
                reason = f"intrinsic error(s): {codes}"
            removed.append(f"{row.ref} [{reason}]")

    if policy == Policy.REJECT_BATCH:
        # full rejection: publish nothing, quarantine everything
        for table in TABLES:
            quarantined[table] = list(result.rows[table])
            published[table] = []
        return PolicyDecision(policy=policy, published=published,
                              quarantined=quarantined,
                              deleted_dependencies=removed, closure_violations=[])

    violations = _closure_violations(published)
    if violations:
        # Defensive: taint BFS should make this unreachable. Fail loudly instead
        # of ever publishing an orphan reference.
        raise RuntimeError("closure invariant violated: " + "; ".join(violations))

    return PolicyDecision(policy=policy, published=published,
                          quarantined=quarantined,
                          deleted_dependencies=removed, closure_violations=[])


def closure_check_csv(published_dir: str) -> list[str]:
    """Standalone check against an exported release directory (for verify CLI)."""
    from .loader import load_batch
    loaded = load_batch(published_dir, batch_id="verify")
    sets = {t: {r.key for r in loaded.rows[t] if r.key} for t in TABLES}
    violations: list[str] = []
    for table, edges in REF_EDGES.items():
        for row in loaded.rows[table]:
            for col, target_table, _optional in edges:
                val = row.values.get(col, "")
                if val and val not in sets[target_table]:
                    violations.append(
                        f"{row.ref}: {col}='{val}' has no published {target_table}")
    return violations
