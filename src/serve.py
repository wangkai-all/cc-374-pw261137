#!/usr/bin/env python3
"""Entry point: python -I src/serve.py [--port 8000] [--reset]"""
from __future__ import annotations

import argparse
import os
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pointwise.web import serve  # noqa: E402

ROOT = os.path.dirname(os.path.abspath(__file__))
DEFAULT_SOURCE = os.path.join(ROOT, "..", "data", "batches", "BATCH-2026-ALPHA")
DEFAULT_WS = os.path.abspath(os.path.join(ROOT, "..", "workspace"))

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--batch-id", default="BATCH-2026-ALPHA")
    ap.add_argument("--source", default=os.path.abspath(DEFAULT_SOURCE))
    ap.add_argument("--workspace", default=DEFAULT_WS)
    ap.add_argument("--reset", action="store_true",
                    help="delete the workspace first for a clean demonstration")
    args = ap.parse_args()
    if args.reset and os.path.isdir(args.workspace):
        shutil.rmtree(args.workspace)
    serve(args.workspace, args.source, args.batch_id, args.host, args.port)
