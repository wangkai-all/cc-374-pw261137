"""SQLite-backed state for crash recovery and pointwise replay."""
from __future__ import annotations

import json
import os
import sqlite3
import threading
from typing import Optional

from .models import Row, Stage, TABLES

SCHEMA = """
CREATE TABLE IF NOT EXISTS batches (
    batch_id        TEXT PRIMARY KEY,
    source_dir      TEXT NOT NULL,
    working_dir     TEXT NOT NULL,
    stage           TEXT NOT NULL,
    policy          TEXT,
    next_version    INTEGER NOT NULL DEFAULT 1,
    source_checksums TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at     TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS row_snapshots (
    batch_id      TEXT NOT NULL,
    table_name    TEXT NOT NULL,
    line_no       INTEGER NOT NULL,
    row_key       TEXT NOT NULL,
    content_hash  TEXT NOT NULL,
    status        TEXT NOT NULL,
    reason_codes  TEXT NOT NULL,
    taint_path    TEXT,
    validated_at  TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (batch_id, table_name, line_no)
);
CREATE TABLE IF NOT EXISTS intrinsic_cache (
    content_hash TEXT PRIMARY KEY,
    findings     TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS releases (
    version       INTEGER PRIMARY KEY,
    batch_id      TEXT NOT NULL,
    policy        TEXT NOT NULL,
    outcome       TEXT NOT NULL,
    release_dir   TEXT NOT NULL,
    quarantine_dir TEXT NOT NULL,
    release_zip   TEXT NOT NULL,
    quarantine_zip TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);
"""


class Store:
    def __init__(self, db_path: str) -> None:
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        # ThreadingHTTPServer serves requests on worker threads; one RLock
        # serializes writes instead of assuming a single thread owns the conn.
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        with self._lock:
            self.conn.executescript(SCHEMA)
            self.conn.commit()

    def close(self) -> None:
        with self._lock:
            self.conn.close()

    # ---------------- batches ----------------
    def upsert_batch(self, batch_id: str, source_dir: str, working_dir: str,
                     stage: Stage, source_checksums: dict,
                     policy: Optional[str] = None) -> None:
        with self._lock:
            self.conn.execute(
                """INSERT INTO batches(batch_id, source_dir, working_dir, stage,
                                       policy, source_checksums)
                   VALUES (?,?,?,?,?,?)
                   ON CONFLICT(batch_id) DO UPDATE SET
                     stage=excluded.stage,
                     policy=COALESCE(excluded.policy, batches.policy),
                     source_checksums=excluded.source_checksums,
                     updated_at=datetime('now')""",
                (batch_id, source_dir, working_dir, stage.value, policy,
                 json.dumps(source_checksums, sort_keys=True)))
            self.conn.commit()

    def set_stage(self, batch_id: str, stage: Stage) -> None:
        with self._lock:
            self.conn.execute(
                "UPDATE batches SET stage=?, updated_at=datetime('now') WHERE batch_id=?",
                (stage.value, batch_id))
            self.conn.commit()

    def set_policy(self, batch_id: str, policy: str) -> None:
        with self._lock:
            self.conn.execute(
                "UPDATE batches SET policy=?, updated_at=datetime('now') WHERE batch_id=?",
                (policy, batch_id))
            self.conn.commit()

    def get_batch(self, batch_id: str) -> Optional[sqlite3.Row]:
        cur = self.conn.execute("SELECT * FROM batches WHERE batch_id=?", (batch_id,))
        return cur.fetchone()

    def bump_version(self, batch_id: str) -> int:
        with self._lock:
            row = self.get_batch(batch_id)
            version = row["next_version"]
            self.conn.execute(
                "UPDATE batches SET next_version=?, updated_at=datetime('now') WHERE batch_id=?",
                (version + 1, batch_id))
            self.conn.commit()
            return version

    # ---------------- row snapshots ----------------
    def replace_snapshots(self, batch_id: str, rows: dict[str, list[Row]]) -> None:
        with self._lock:
            self.conn.execute("DELETE FROM row_snapshots WHERE batch_id=?", (batch_id,))
            payload = [
                (batch_id, table, r.line_no, r.key, r.content_hash, r.status,
                 json.dumps(sorted({f.code for f in r.intrinsic_errors})),
                 json.dumps([c.to_dict() for c in r.taint_path]) if r.taint_path else None)
                for table in TABLES for r in rows[table]
            ]
            self.conn.executemany(
                """INSERT INTO row_snapshots(batch_id, table_name, line_no, row_key,
                                             content_hash, status, reason_codes, taint_path)
                   VALUES (?,?,?,?,?,?,?,?)""", payload)
            self.conn.commit()

    def get_snapshot(self, batch_id: str, table: str, line_no: int):
        cur = self.conn.execute(
            "SELECT * FROM row_snapshots WHERE batch_id=? AND table_name=? AND line_no=?",
            (batch_id, table, line_no))
        return cur.fetchone()

    def list_snapshots(self, batch_id: str) -> list[sqlite3.Row]:
        cur = self.conn.execute(
            "SELECT * FROM row_snapshots WHERE batch_id=? ORDER BY table_name, line_no",
            (batch_id,))
        return cur.fetchall()

    # ---------------- intrinsic cache ----------------
    def load_cache(self) -> dict[str, list[dict]]:
        return {row["content_hash"]: json.loads(row["findings"])
                for row in self.conn.execute("SELECT * FROM intrinsic_cache")}

    def save_cache_entry(self, content_hash: str, findings: list[dict]) -> None:
        with self._lock:
            self.conn.execute(
                """INSERT INTO intrinsic_cache(content_hash, findings) VALUES (?,?)
                   ON CONFLICT(content_hash) DO UPDATE SET findings=excluded.findings""",
                (content_hash, json.dumps(findings)))
            self.conn.commit()

    # ---------------- releases ----------------
    def record_release(self, version: int, batch_id: str, policy: str, outcome: str,
                       paths: dict) -> None:
        with self._lock:
            self.conn.execute(
                """INSERT INTO releases(version, batch_id, policy, outcome, release_dir,
                                        quarantine_dir, release_zip, quarantine_zip)
                   VALUES (?,?,?,?,?,?,?,?)
                   ON CONFLICT(version) DO UPDATE SET
                     outcome=excluded.outcome, release_dir=excluded.release_dir,
                     quarantine_dir=excluded.quarantine_dir,
                     release_zip=excluded.release_zip,
                     quarantine_zip=excluded.quarantine_zip""",
                (version, batch_id, policy, outcome, paths["release_dir"],
                 paths["quarantine_dir"], paths["release_zip"], paths["quarantine_zip"]))
            self.conn.commit()

    def list_releases(self, batch_id: str) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM releases WHERE batch_id=? ORDER BY version",
            (batch_id,)).fetchall()
