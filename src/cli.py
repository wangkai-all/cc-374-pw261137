#!/usr/bin/env python3
"""Command line interface for the pointwise-restart pipeline.

Everything works offline with the Python standard library only.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pointwise import PointwisePipeline, Policy, verify_release  # noqa: E402

DEFAULT_WS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "workspace")
DEFAULT_WS = os.path.abspath(DEFAULT_WS)


def _print(obj) -> None:
    print(json.dumps(obj, indent=2, ensure_ascii=False, default=str))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Pointwise-restart pipeline CLI")
    parser.add_argument("--workspace", default=DEFAULT_WS,
                        help="pipeline workspace directory")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("receive", help="receive and checksum a batch")
    p.add_argument("source_dir")
    p.add_argument("--batch-id", required=True)

    sub.add_parser("validate", help="run validator").add_argument("--batch-id", required=True)

    p = sub.add_parser("publish", help="apply policy and publish a release")
    p.add_argument("--batch-id", required=True)
    p.add_argument("--policy", choices=[m.value for m in Policy],
                   default=Policy.RETAIN_CLEAN_SUBSET.value)
    p.add_argument("--crash", choices=["pre_publish", "mid_publish"], default=None)

    p = sub.add_parser("resume", help="recover after a simulated crash")
    p.add_argument("--batch-id", required=True)

    p = sub.add_parser("fix", help="correct one row of one table")
    p.add_argument("--batch-id", required=True)
    p.add_argument("--table", required=True,
                   choices=["accounts", "relationships", "transactions"])
    p.add_argument("--line", type=int, required=True)
    p.add_argument("--set", dest="assignments", action="append", default=[],
                   help="column=value, repeatable")

    p = sub.add_parser("replay", help="minimal replay after a fix")
    p.add_argument("--batch-id", required=True)

    p = sub.add_parser("rereceive", help="restore working copy from immutable source")
    p.add_argument("--batch-id", required=True)

    p = sub.add_parser("query", help="query a row by key: status, chain, fix impact")
    p.add_argument("--batch-id", required=True)
    p.add_argument("--key", required=True)
    p.add_argument("--table", default=None,
                   choices=["accounts", "relationships", "transactions"])

    p = sub.add_parser("status", help="show persisted batch state")
    p.add_argument("--batch-id", required=True)

    p = sub.add_parser("verify", help="verify a release directory")
    p.add_argument("release_dir")

    p = sub.add_parser("demo", help="end-to-end demonstration on synthetic data")
    p.add_argument("--source", default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..",
        "data", "batches", "BATCH-2026-ALPHA"))
    p.add_argument("--batch-id", default="BATCH-2026-ALPHA")

    args = parser.parse_args(argv)
    pipe = PointwisePipeline(args.workspace)
    try:
        if args.cmd == "receive":
            _print(pipe.receive(args.source_dir, args.batch_id))
        elif args.cmd == "validate":
            _print(pipe.validate(args.batch_id))
        elif args.cmd == "publish":
            _print(pipe.publish(args.batch_id, Policy(args.policy), crash=args.crash))
        elif args.cmd == "resume":
            _print(pipe.resume(args.batch_id))
        elif args.cmd == "fix":
            updates = dict(a.split("=", 1) for a in args.assignments)
            _print(pipe.fix_row(args.batch_id, args.table, args.line, updates))
        elif args.cmd == "replay":
            _print(pipe.replay(args.batch_id))
        elif args.cmd == "rereceive":
            _print(pipe.rereceive(args.batch_id))
        elif args.cmd == "query":
            _print(pipe.query_row(args.batch_id, args.key, args.table))
        elif args.cmd == "status":
            _print(pipe.status(args.batch_id))
        elif args.cmd == "verify":
            _print(verify_release(args.release_dir))
        elif args.cmd == "demo":
            return run_demo(pipe, args.source, args.batch_id)
    finally:
        pipe.close()
    return 0


def run_demo(pipe: PointwisePipeline, source: str, batch_id: str) -> int:
    print("== 1. RECEIVE ==")
    _print(pipe.receive(source, batch_id))
    print("\n== 2. VALIDATE (intrinsic checks + reference taint closure) ==")
    res = pipe.validate(batch_id)
    print(json.dumps(res["stats"], indent=2))
    print("cache misses (first validation):", len(res["cache"]["misses"]))

    print("\n== 3. PUBLISH clean subset (v1) ==")
    out = pipe.publish(batch_id, Policy.RETAIN_CLEAN_SUBSET)
    print("release:", out["release_dir"])
    print("quarantine:", out["quarantine_dir"])
    _print(verify_release(out["release_dir"])["verified"] and "RELEASE VERIFIED: checksums ok, zero orphan references")

    print("\n== 4. SIMULATED CRASH: validation done, crash BEFORE publish ==")
    crash_out = pipe.publish(batch_id, Policy.RETAIN_CLEAN_SUBSET, crash="pre_publish")
    _print(crash_out)
    print("-- restart process; resume without re-validation --")
    rec = pipe.resume(batch_id)
    _print({"version": rec["version"], "recovered_from": rec["recovered_from"]})
    _print(verify_release(rec["release_dir"])["verified"] and "RECOVERED RELEASE VERIFIED")

    print("\n== 5. SIMULATED CRASH DURING publish (staged, not committed) ==")
    crash_out = pipe.publish(batch_id, Policy.RETAIN_CLEAN_SUBSET, crash="mid_publish")
    _print({k: crash_out[k] for k in ("crashed", "version", "staging_release")})
    rec = pipe.resume(batch_id)
    _print({"recovered": rec.get("recovered"), "version": rec["version"]})

    print("\n== 6. POINTWISE FIX: correct ACC-1002 negative balance (line 2) ==")
    _print(pipe.fix_row(batch_id, "accounts", 2, {"balance": "315.25"}))
    replay = pipe.replay(batch_id)
    _print(replay["replay"])
    print("cache hits on replay:", len(replay["cache"]["hits"]),
          "| cache misses:", len(replay["cache"]["misses"]))

    print("\n== 7. RE-PUBLISH after fix (new immutable version) ==")
    out2 = pipe.publish(batch_id, Policy.RETAIN_CLEAN_SUBSET)
    _print({"version": out2["version"], "stats": out2["stats"]["per_table"]})
    _print(verify_release(out2["release_dir"])["verified"] and "v-NEXT RELEASE VERIFIED")

    print("\n== 8. FULL-BATCH REJECTION policy ==")
    rej = pipe.publish(batch_id, Policy.REJECT_BATCH)
    _print({"version": rej["version"], "manifest_outcome": rej["manifest"]["outcome"]})
    print("\nDownloadable artifacts in:", os.path.join(pipe.workspace, "downloads"))
    for name in sorted(os.listdir(os.path.join(pipe.workspace, "downloads"))):
        print("  -", name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
