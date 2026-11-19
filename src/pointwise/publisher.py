"""Publisher and handback manifest.

Assembly happens in a hidden staging directory and is committed by a single
atomic rename, so a crash at any point leaves either the previous complete
release or the new one - never a half-written directory. Two downloadable
artifacts are produced per release:

  release-vN.zip      - published subset (or an empty release on full rejection)
  quarantine-vN.zip   - every excluded row with reason + remediation + re-ingest guide

Both carry a CHECKSUMS.sha256 file; `verify_release` independently re-checks
hashes and re-checks referential closure on the unpacked release directory.
"""
from __future__ import annotations

import csv
import hashlib
import json
import os
import shutil
import zipfile

from .loader import PRIMARY_KEY, sha256_file
from .models import ERROR_CATALOG, Policy, Row, TABLES
from .policy import PolicyDecision, closure_check_csv
from .validator import ValidationResult

QUARANTINE_EXTRA = ["_quarantine_reason", "_dependency_chain", "_remediation"]


def _write_csv(path: str, headers: list[str], rows: list[Row],
               extra_cols: list[str] | None = None) -> None:
    cols = headers + (extra_cols or [])
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=cols)
        writer.writeheader()
        for row in rows:
            record = {h: row.values.get(h, "") for h in headers}
            if extra_cols:
                if row.taint_path:
                    chain = " -> ".join(
                        f"{c.table}:{c.key or '<missing-key>'}(L{c.line_no})"
                        for c in row.taint_path)
                    record["_quarantine_reason"] = "TAINT"
                    record["_dependency_chain"] = chain
                    record["_remediation"] = ERROR_CATALOG["E_TAINTED"]
                else:
                    codes = sorted({f.code for f in row.intrinsic_errors})
                    record["_quarantine_reason"] = ";".join(codes)
                    record["_dependency_chain"] = ""
                    record["_remediation"] = " | ".join(
                        ERROR_CATALOG.get(c, c) for c in codes)
            writer.writerow(record)


def _sha256_of_files(root: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for dirpath, _dirs, files in os.walk(root):
        for name in sorted(files):
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            if rel == "CHECKSUMS.sha256":
                continue
            out[rel] = sha256_file(full)
    return out


def _write_checksums(root: str) -> None:
    sums = _sha256_of_files(root)
    with open(os.path.join(root, "CHECKSUMS.sha256"), "w", encoding="utf-8") as fh:
        for rel, digest in sorted(sums.items()):
            fh.write(f"{digest}  {rel}\n")


def _zip_dir(src_dir: str, zip_path: str) -> None:
    if os.path.exists(zip_path):
        os.remove(zip_path)
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for dirpath, _dirs, files in os.walk(src_dir):
            for name in sorted(files):
                full = os.path.join(dirpath, name)
                zf.write(full, os.path.relpath(full, src_dir))


def _chain_payload(row: Row) -> list[dict]:
    if not row.taint_path:
        return []
    return [c.to_dict() for c in row.taint_path]


def build_manifest(batch_id: str, version: int, policy: Policy,
                   decision: PolicyDecision, result: ValidationResult,
                   source_checksums: dict[str, str]) -> dict:
    quarantined_rows = []
    for table in TABLES:
        for row in decision.quarantined[table]:
            quarantined_rows.append({
                "table": table,
                "key": row.key or "<missing-key>",
                "source_line": row.line_no,
                "reason_codes": sorted({f.code for f in row.intrinsic_errors})
                                or (["E_TAINTED"] if row.taint_path else []),
                "dependency_chain": _chain_payload(row),
                "remediation": " | ".join(
                    ERROR_CATALOG.get(c, c) for c in
                    (sorted({f.code for f in row.intrinsic_errors})
                     or (["E_TAINTED"] if row.taint_path else []))),
            })
    published_counts = {t: len(decision.published[t]) for t in TABLES}
    quarantined_counts = {t: len(decision.quarantined[t]) for t in TABLES}
    return {
        "batch_id": batch_id,
        "release_version": version,
        "policy": policy.value,
        "outcome": "REJECTED - no rows published"
                   if policy == Policy.REJECT_BATCH
                   else "SUBSET PUBLISHED - referentially closed",
        "source_file_checksums": source_checksums,
        "counts": {"published": published_counts,
                   "quarantined": quarantined_counts},
        "missing_references": [m.to_dict() for m in result.missing_refs],
        "quarantined_rows": quarantined_rows,
        "deleted_dependency_notes": decision.deleted_dependencies,
        "closure_violations": decision.closure_violations,
        "reingest_guide": {
            "steps": [
                "1. Correct each quarantined row in the source system using its "
                "remediation text (or supply the missing referenced row).",
                "2. Keep original primary keys stable so repaired rows rejoin the graph.",
                "3. Re-ingest the repaired batch; the validator reuses cached "
                "intrinsic verdicts for unchanged rows and only re-runs affected ones.",
                "4. A new release version is published atomically; prior versions "
                "remain on disk and are never overwritten.",
            ],
            "no_orphan_guarantee": "Every reference inside the published release "
                                   "resolves to a row inside the same release.",
        },
    }


def publish_release(workspace: str, batch_id: str, version: int, policy: Policy,
                    decision: PolicyDecision, result: ValidationResult,
                    headers: dict[str, list[str]],
                    source_checksums: dict[str, str],
                    crash_mid_publish: bool = False) -> dict:
    """Assemble release + quarantine under staging/, then atomically rename.

    crash_mid_publish=True simulates the process dying after files are staged
    but before the commit rename. The staging directory is deliberately left
    behind so recovery can prove idempotent resume; the live release pointer is
    never advanced.
    """
    releases_root = os.path.join(workspace, "releases")
    quarantine_root = os.path.join(workspace, "quarantine")
    staging_root = os.path.join(workspace, "staging")
    downloads = os.path.join(workspace, "downloads")
    for d in (releases_root, quarantine_root, staging_root, downloads):
        os.makedirs(d, exist_ok=True)

    stage_rel = os.path.join(staging_root, f"release-v{version}")
    stage_quar = os.path.join(staging_root, f"quarantine-v{version}")
    shutil.rmtree(stage_rel, ignore_errors=True)
    shutil.rmtree(stage_quar, ignore_errors=True)
    os.makedirs(stage_rel)
    os.makedirs(stage_quar)

    # --- stage published subset ---------------------------------------------
    for table in TABLES:
        _write_csv(os.path.join(stage_rel, f"{table}.csv"),
                   headers[table], decision.published[table])
    manifest = build_manifest(batch_id, version, policy, decision, result,
                              source_checksums)
    with open(os.path.join(stage_rel, "release-manifest.json"), "w",
              encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, ensure_ascii=False)
    _write_checksums(stage_rel)

    # --- stage quarantine bundle --------------------------------------------
    for table in TABLES:
        _write_csv(os.path.join(stage_quar, f"{table}.csv"),
                   headers[table], decision.quarantined[table],
                   extra_cols=QUARANTINE_EXTRA)
    with open(os.path.join(stage_quar, "handback-manifest.json"), "w",
              encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, ensure_ascii=False)
    _write_checksums(stage_quar)

    if crash_mid_publish:
        return {"crashed": True, "staging_release": stage_rel,
                "staging_quarantine": stage_quar,
                "note": "simulated crash after staging, before atomic commit; "
                        "no release pointer advanced"}

    # --- atomic commit: content-addressed dirs then one rename each ---------
    final_rel = os.path.join(releases_root, f"v{version}")
    final_quar = os.path.join(quarantine_root, f"v{version}")
    shutil.rmtree(final_rel, ignore_errors=True)
    shutil.rmtree(final_quar, ignore_errors=True)
    os.rename(stage_rel, final_rel)
    os.rename(stage_quar, final_quar)

    zip_rel = os.path.join(downloads, f"release-v{version}.zip")
    zip_quar = os.path.join(downloads, f"quarantine-v{version}.zip")
    _zip_dir(final_rel, zip_rel)
    _zip_dir(final_quar, zip_quar)

    return {"crashed": False, "release_dir": final_rel,
            "quarantine_dir": final_quar,
            "release_zip": zip_rel, "quarantine_zip": zip_quar,
            "manifest": manifest}


def resume_publish(workspace: str, version: int) -> dict:
    """Idempotent recovery from a mid-publish crash.

    Staged content is checksum-verified and then committed with the same atomic
    rename. Running it twice is safe: after the first commit the staging dirs
    are gone and the second call is a no-op.
    """
    staging_root = os.path.join(workspace, "staging")
    stage_rel = os.path.join(staging_root, f"release-v{version}")
    stage_quar = os.path.join(staging_root, f"quarantine-v{version}")
    final_rel = os.path.join(workspace, "releases", f"v{version}")
    final_quar = os.path.join(workspace, "quarantine", f"v{version}")

    if os.path.isdir(final_rel) and os.path.isdir(final_quar):
        return {"recovered": False, "note": "release already committed; resume is a no-op"}
    if not os.path.isdir(stage_rel) or not os.path.isdir(stage_quar):
        raise FileNotFoundError("no staged content found; a full re-publish is required")

    # verify staged checksums before trusting them
    for stage in (stage_rel, stage_quar):
        ok, bad = _verify_checksums(stage)
        if not ok:
            raise RuntimeError(f"staged content corrupted in {stage}: {bad}")

    os.makedirs(os.path.dirname(final_rel), exist_ok=True)
    os.makedirs(os.path.dirname(final_quar), exist_ok=True)
    shutil.rmtree(final_rel, ignore_errors=True)
    shutil.rmtree(final_quar, ignore_errors=True)
    os.rename(stage_rel, final_rel)
    os.rename(stage_quar, final_quar)

    downloads = os.path.join(workspace, "downloads")
    os.makedirs(downloads, exist_ok=True)
    zip_rel = os.path.join(downloads, f"release-v{version}.zip")
    zip_quar = os.path.join(downloads, f"quarantine-v{version}.zip")
    _zip_dir(final_rel, zip_rel)
    _zip_dir(final_quar, zip_quar)
    return {"recovered": True, "release_dir": final_rel,
            "quarantine_dir": final_quar,
            "release_zip": zip_rel, "quarantine_zip": zip_quar}


def _verify_checksums(root: str) -> tuple[bool, list[str]]:
    sums_path = os.path.join(root, "CHECKSUMS.sha256")
    if not os.path.exists(sums_path):
        return False, ["CHECKSUMS.sha256 missing"]
    bad: list[str] = []
    with open(sums_path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            digest, rel = line.split("  ", 1)
            full = os.path.join(root, rel)
            if not os.path.exists(full) or sha256_file(full) != digest:
                bad.append(rel)
    return not bad, bad


def verify_release(release_dir: str) -> dict:
    """Independent verification: checksums + referential closure on a release."""
    ok, bad = _verify_checksums(release_dir)
    closure = closure_check_csv(release_dir)
    manifest_path = os.path.join(release_dir, "release-manifest.json")
    manifest = None
    if os.path.exists(manifest_path):
        with open(manifest_path, encoding="utf-8") as fh:
            manifest = json.load(fh)
    return {
        "release_dir": release_dir,
        "checksums_ok": ok,
        "checksum_mismatches": bad,
        "orphan_references": closure,
        "closure_ok": not closure,
        "verified": ok and not closure,
        "manifest": manifest,
    }
