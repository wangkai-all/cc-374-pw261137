"""Pipeline orchestration: receive -> validate -> (crash) -> publish,
plus pointwise fix with minimal replay.
"""
from __future__ import annotations

import csv
import os
import shutil
from typing import Optional

from .loader import load_batch, LoadedBatch, PRIMARY_KEY
from .models import Policy, Stage, TABLES
from .policy import apply_policy
from .publisher import publish_release, resume_publish
from .store import Store
from .validator import IntrinsicCache, Validator, ValidationResult


class PointwisePipeline:
    def __init__(self, workspace_dir: str) -> None:
        self.workspace = os.path.abspath(workspace_dir)
        os.makedirs(self.workspace, exist_ok=True)
        self.store = Store(os.path.join(self.workspace, "pipeline.db"))
        self.cache = IntrinsicCache(self.store.load_cache())

    def close(self) -> None:
        self.store.close()

    # ---------------------------------------------------------------- receive
    def receive(self, source_dir: str, batch_id: str) -> dict:
        working = os.path.join(self.workspace, "batches", batch_id)
        os.makedirs(working, exist_ok=True)
        # copy source CSVs into the workspace; originals stay untouched evidence
        for name in os.listdir(source_dir):
            if name.endswith(".csv"):
                shutil.copy2(os.path.join(source_dir, name),
                             os.path.join(working, name))
        loaded = load_batch(working, batch_id)
        self.store.upsert_batch(batch_id, os.path.abspath(source_dir), working,
                                Stage.RECEIVED, loaded.source_checksums)
        return {"batch_id": batch_id, "working_dir": working,
                "checksums": loaded.source_checksums,
                "rows": {t: len(loaded.rows[t]) for t in loaded.rows}}

    def _load(self, batch_id: str) -> LoadedBatch:
        row = self.store.get_batch(batch_id)
        if row is None:
            raise KeyError(f"unknown batch: {batch_id}")
        return load_batch(row["working_dir"], batch_id)

    def rereceive(self, batch_id: str) -> dict:
        """Discard working-copy edits and restore the batch from immutable
        source CSVs. Cached intrinsic verdicts and published releases are kept.
        """
        row = self.store.get_batch(batch_id)
        if row is None:
            raise KeyError(f"unknown batch: {batch_id}")
        source_dir = row["source_dir"]
        working = row["working_dir"]
        for name in os.listdir(source_dir):
            if name.endswith(".csv"):
                shutil.copy2(os.path.join(source_dir, name),
                             os.path.join(working, name))
        loaded = load_batch(working, batch_id)
        self.store.upsert_batch(batch_id, source_dir, working,
                                Stage.RECEIVED, loaded.source_checksums)
        self.store.replace_snapshots(batch_id, loaded.rows)
        return {"batch_id": batch_id, "restored_from": source_dir,
                "checksums": loaded.source_checksums,
                "rows": {t: len(loaded.rows[t]) for t in loaded.rows},
                "note": "working copy restored from source; cache and releases retained"}

    def query_row(self, batch_id: str, key: str,
                  table: Optional[str] = None) -> dict:
        """Look up a row by primary key across the three tables and report its
        validation status, findings, dependency chain, and the reverse-closure
        of rows that would be affected if this row changed.
        """
        loaded = self._load(batch_id)
        matches = [r for t in TABLES for r in loaded.rows[t]
                   if r.key == key and (table is None or t == table)]
        if not matches:
            return {"key": key, "found": False, "matches": []}
        result = Validator(self.cache).validate(loaded)
        out_matches = []
        for r in matches:
            vr = next(x for t in TABLES for x in result.rows[t]
                      if x.table == r.table and x.line_no == r.line_no)
            changed = [{"table": vr.table, "line_no": vr.line_no, "key": vr.key}]
            scope = self._replay_scope(loaded, changed)
            out_matches.append({
                "table": vr.table, "line_no": vr.line_no, "key": vr.key,
                "status": vr.status, "values": vr.values,
                "intrinsic_codes": sorted({f.code for f in vr.intrinsic_errors}),
                "findings": [f.to_dict() for f in vr.intrinsic_errors],
                "taint_path": [c.to_dict() for c in vr.taint_path]
                               if vr.taint_path else [],
                "reverse_closure": scope,
                "reverse_closure_count": len(scope),
            })
        return {"key": key, "found": True, "matches": out_matches}

    # -------------------------------------------------------------- validate
    def validate(self, batch_id: str) -> dict:
        self.store.set_stage(batch_id, Stage.VALIDATING)
        loaded = self._load(batch_id)
        validator = Validator(self.cache)
        result = validator.validate(loaded)
        for content_hash in result.cache_misses:
            self.store.save_cache_entry(
                content_hash, self.cache.get(content_hash))
        self.store.replace_snapshots(batch_id, result.rows)
        self.store.set_stage(batch_id, Stage.VALIDATED)
        return self._result_payload(batch_id, result, loaded, replay=None)

    # --------------------------------------------------------------- publish
    def publish(self, batch_id: str, policy: Policy,
                crash: Optional[str] = None) -> dict:
        """crash: None | 'pre_publish' | 'mid_publish'."""
        self.store.set_policy(batch_id, policy.value)
        loaded = self._load(batch_id)
        result = Validator(self.cache).validate(loaded)
        decision = apply_policy(result, policy)

        if crash == "pre_publish":
            # process dies after validation finished, before publish starts
            self.store.set_stage(batch_id, Stage.CRASHED_PRE_PUBLISH)
            return {"crashed": "pre_publish", "stage": Stage.CRASHED_PRE_PUBLISH.value,
                    "note": "validation results are durable; publish never started; "
                            "recover with resume() - no re-validation needed"}

        self.store.set_stage(batch_id, Stage.PUBLISHING)
        version = self.store.bump_version(batch_id)
        outcome = publish_release(
            self.workspace, batch_id, version, policy, decision, result,
            loaded.headers, loaded.source_checksums,
            crash_mid_publish=(crash == "mid_publish"))

        if outcome.get("crashed"):
            self.store.set_stage(batch_id, Stage.CRASHED_DURING_PUBLISH)
            outcome["version"] = version
            outcome["stage"] = Stage.CRASHED_DURING_PUBLISH.value
            return outcome

        self.store.record_release(
            version, batch_id, policy.value,
            "REJECTED" if policy == Policy.REJECT_BATCH else "SUBSET",
            outcome)
        self.store.set_stage(batch_id, Stage.PUBLISHED)
        outcome["version"] = version
        outcome["stats"] = result.stats
        return outcome

    def resume(self, batch_id: str) -> dict:
        """Recover from either simulated crash without re-validating."""
        row = self.store.get_batch(batch_id)
        stage = Stage(row["stage"])
        if stage == Stage.CRASHED_PRE_PUBLISH:
            # nothing was staged; run the publish step using durable validation
            self.store.set_stage(batch_id, Stage.PUBLISHING)
            loaded = self._load(batch_id)
            result = Validator(self.cache).validate(loaded)
            policy = Policy(row["policy"]) if row["policy"] else Policy.RETAIN_CLEAN_SUBSET
            decision = apply_policy(result, policy)
            version = self.store.bump_version(batch_id)
            outcome = publish_release(self.workspace, batch_id, version, policy,
                                      decision, result, loaded.headers,
                                      loaded.source_checksums)
            self.store.record_release(
                version, batch_id, policy.value,
                "REJECTED" if policy == Policy.REJECT_BATCH else "SUBSET", outcome)
            self.store.set_stage(batch_id, Stage.PUBLISHED)
            outcome["version"] = version
            outcome["recovered_from"] = stage.value
            return outcome

        if stage == Stage.CRASHED_DURING_PUBLISH:
            # next_version was already bumped; derive the staged version number
            version = row["next_version"] - 1
            outcome = resume_publish(self.workspace, version)
            if outcome.get("recovered"):
                loaded = self._load(batch_id)
                policy = Policy(row["policy"]) if row["policy"] else Policy.RETAIN_CLEAN_SUBSET
                self.store.record_release(
                    version, batch_id, policy.value,
                    "REJECTED" if policy == Policy.REJECT_BATCH else "SUBSET", outcome)
            self.store.set_stage(batch_id, Stage.PUBLISHED)
            outcome["version"] = version
            outcome["recovered_from"] = stage.value
            return outcome

        return {"recovered_from": None, "note": f"no crash to recover from (stage={stage.value})"}

    # -------------------------------------------------- pointwise fix + replay
    def fix_row(self, batch_id: str, table: str, line_no: int,
                updates: dict[str, str]) -> dict:
        """Apply one corrected row to the working CSV (atomic per-file write)."""
        row = self.store.get_batch(batch_id)
        path = os.path.join(row["working_dir"], f"{table}.csv")
        with open(path, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            fieldnames = list(reader.fieldnames or [])
            records = list(reader)
        idx = line_no - 1
        if not (0 <= idx < len(records)):
            raise IndexError(f"line {line_no} does not exist in {table}.csv")
        for col, val in updates.items():
            if col not in fieldnames:
                raise KeyError(f"unknown column {col} in {table}")
            records[idx][col] = val
        tmp = path + ".tmp"
        with open(tmp, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(records)
        os.replace(tmp, path)
        return {"table": table, "line_no": line_no, "updates": updates,
                "row_key": records[idx].get(PRIMARY_KEY[table], "")}

    def replay(self, batch_id: str, changed: Optional[dict] = None) -> dict:
        """Re-validate after a fix.

        Unchanged rows hit the intrinsic cache (zero recomputation); changed
        rows recompute, and graph-level checks (duplicates, FKs, taint closure)
        always rerun so the full propagation is rebuilt correctly.
        """
        before: dict[tuple[str, int], str] = {
            (s["table_name"], s["line_no"]): s["content_hash"]
            for s in self.store.list_snapshots(batch_id)}
        loaded = self._load(batch_id)

        changed_rows: list[dict] = []
        for r in loaded.all_rows():
            if before.get((r.table, r.line_no)) != r.content_hash:
                changed_rows.append({"table": r.table, "line_no": r.line_no,
                                     "key": r.key})

        validator = Validator(self.cache)
        result = validator.validate(loaded)
        for content_hash in result.cache_misses:
            self.store.save_cache_entry(content_hash, self.cache.get(content_hash))
        self.store.replace_snapshots(batch_id, result.rows)
        self.store.set_stage(batch_id, Stage.VALIDATED)

        # replay scope = transitive reverse-closure of changed rows in the
        # current reference graph (these rows got a new verdict)
        scope = self._replay_scope(loaded, changed_rows)
        return self._result_payload(
            batch_id, result, loaded,
            replay={"changed_rows": changed_rows,
                    "cache_hits": sorted(result.cache_hits),
                    "cache_misses": sorted(result.cache_misses),
                    "replayed_rows": scope,
                    "replayed_count": len(scope),
                    "reused_count": result.stats["total_rows"] - len(scope)})

    def _replay_scope(self, loaded: LoadedBatch, changed_rows: list[dict]) -> list[dict]:
        from .validator import REF_EDGES
        index: dict[tuple[str, str], list] = {}
        for r in loaded.all_rows():
            if r.key:
                index.setdefault((r.table, r.key), []).append(r)
        seen: set[str] = set()
        queue = list(changed_rows)
        scope: list[dict] = []
        while queue:
            item = queue.pop(0)
            row = next((r for r in loaded.rows[item["table"]]
                        if r.line_no == item["line_no"]), None)
            if row is None or row.ref in seen:
                continue
            seen.add(row.ref)
            scope.append({"table": row.table, "line_no": row.line_no, "key": row.key})
            # find rows referencing this row's key
            for table, edges in REF_EDGES.items():
                for candidate in loaded.rows[table]:
                    for col, target_table, _opt in edges:
                        if target_table == row.table and \
                                candidate.values.get(col) == row.key and row.key:
                            queue.append({"table": table,
                                          "line_no": candidate.line_no, "key": candidate.key})
        return scope

    # ---------------------------------------------------------------- helpers
    def status(self, batch_id: str) -> dict:
        row = self.store.get_batch(batch_id)
        if row is None:
            raise KeyError(f"unknown batch: {batch_id}")
        releases = [dict(r) for r in self.store.list_releases(batch_id)]
        snapshots = [dict(s) for s in self.store.list_snapshots(batch_id)]
        return {"batch_id": batch_id, "stage": row["stage"], "policy": row["policy"],
                "next_version": row["next_version"],
                "working_dir": row["working_dir"],
                "source_dir": row["source_dir"],
                "source_checksums": __import__("json").loads(row["source_checksums"]),
                "releases": releases, "snapshots": snapshots}

    def latest_validation(self, batch_id: str) -> dict:
        loaded = self._load(batch_id)
        result = Validator(self.cache).validate(loaded)
        return self._result_payload(batch_id, result, loaded, replay=None)

    def _result_payload(self, batch_id: str, result: ValidationResult,
                        loaded: LoadedBatch, replay: Optional[dict]) -> dict:
        return {
            "batch_id": batch_id,
            "stats": result.stats,
            "findings": [f.to_dict() for f in result.findings],
            "missing_refs": [m.to_dict() for m in result.missing_refs],
            "rows": {
                table: [{"line_no": r.line_no, "key": r.key, "status": r.status,
                         "content_hash": r.content_hash,
                         "intrinsic_codes": sorted({f.code for f in r.intrinsic_errors}),
                         "taint_path": [c.to_dict() for c in r.taint_path]
                                       if r.taint_path else [],
                         "values": r.values}
                        for r in result.rows[table]]
                for table in result.rows
            },
            "cache": {"hits": sorted(result.cache_hits),
                      "misses": sorted(result.cache_misses)},
            "replay": replay,
        }
