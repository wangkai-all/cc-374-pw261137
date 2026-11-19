"""Receiver: load a batch from CSV, checksum every file, never mutate inputs."""
from __future__ import annotations

import csv
import hashlib
import os
from dataclasses import dataclass

from .models import Row, TABLES

PRIMARY_KEY = {
    "accounts": "account_id",
    "relationships": "relationship_id",
    "transactions": "transaction_id",
}


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass
class LoadedBatch:
    batch_id: str
    batch_dir: str
    rows: dict[str, list[Row]]
    source_checksums: dict[str, str]
    headers: dict[str, list[str]]

    def all_rows(self) -> list[Row]:
        return [r for table in TABLES for r in self.rows[table]]


def load_batch(batch_dir: str, batch_id: str | None = None) -> LoadedBatch:
    """Read the three CSVs. Input files are treated as immutable evidence."""
    batch_id = batch_id or os.path.basename(os.path.normpath(batch_dir))
    rows: dict[str, list[Row]] = {}
    checksums: dict[str, str] = {}
    headers: dict[str, list[str]] = {}
    for table in TABLES:
        path = os.path.join(batch_dir, f"{table}.csv")
        if not os.path.exists(path):
            raise FileNotFoundError(f"required table missing: {path}")
        checksums[table + ".csv"] = sha256_file(path)
        with open(path, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            headers[table] = list(reader.fieldnames or [])
            table_rows: list[Row] = []
            for i, raw in enumerate(reader, start=1):
                values = {k: (v.strip() if isinstance(v, str) else v) for k, v in raw.items()}
                key = values.get(PRIMARY_KEY[table], "") or ""
                table_rows.append(Row(table=table, line_no=i, key=key, values=values))
        rows[table] = table_rows
    return LoadedBatch(batch_id=batch_id, batch_dir=batch_dir, rows=rows,
                       source_checksums=checksums, headers=headers)
