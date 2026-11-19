"""HTTP server: REST API + static single-page UI. Standard library only."""
from __future__ import annotations

import json
import mimetypes
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from .models import Policy
from .pipeline import PointwisePipeline

WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "web")


class Handler(BaseHTTPRequestHandler):
    pipeline: PointwisePipeline = None  # injected by serve()
    batch_id: str = ""

    def log_message(self, fmt, *args) -> None:  # quieter logs
        pass

    # ----------------------------------------------------------------- utils
    def _json(self, payload, status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _file(self, path: str) -> None:
        if not os.path.isfile(path):
            self._json({"error": "not found", "path": path}, 404)
            return
        ctype = mimetypes.guess_type(path)[0] or "application/octet-stream"
        with open(path, "rb") as fh:
            body = fh.read()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        if not length:
            return {}
        return json.loads(self.rfile.read(length).decode("utf-8"))

    # ------------------------------------------------------------------- GET
    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path, qs = parsed.path, parse_qs(parsed.query)
        try:
            if path == "/api/status":
                return self._json(self.pipeline.status(self.batch_id))
            if path == "/api/validation":
                return self._json(self.pipeline.latest_validation(self.batch_id))
            if path == "/api/releases":
                st = self.pipeline.status(self.batch_id)
                return self._json({"releases": st["releases"]})
            if path == "/api/query":
                key = qs.get("key", [""])[0].strip()
                table = qs.get("table", [""])[0].strip() or None
                if not key:
                    return self._json({"error": "query parameter 'key' is required"}, 400)
                return self._json(
                    self.pipeline.query_row(self.batch_id, key, table))
            if path == "/api/download":
                name = qs.get("file", [""])[0]
                safe = os.path.basename(name)
                full = os.path.join(self.pipeline.workspace, "downloads", safe)
                if not safe or not os.path.isfile(full):
                    return self._json({"error": "artifact not found"}, 404)
                return self._file(full)
            if path == "/api/manifest":
                version = int(qs["version"][0])
                kind = qs.get("kind", ["release"])[0]
                leaf = "release-manifest.json" if kind == "release" else "handback-manifest.json"
                sub = "releases" if kind == "release" else "quarantine"
                full = os.path.join(self.pipeline.workspace, sub, f"v{version}", leaf)
                if not os.path.isfile(full):
                    return self._json({"error": "manifest not found"}, 404)
                with open(full, encoding="utf-8") as fh:
                    return self._json(json.load(fh))
            # static UI
            if path in ("/", "/index.html"):
                return self._file(os.path.join(WEB_DIR, "static", "index.html"))
            if path.startswith("/static/"):
                return self._file(os.path.join(WEB_DIR, "static", os.path.basename(path)))
            self._json({"error": "unknown route", "path": path}, 404)
        except Exception as exc:  # noqa: BLE001 - surface as API error
            self._json({"error": type(exc).__name__, "detail": str(exc)}, 500)

    # ------------------------------------------------------------------ POST
    def do_POST(self) -> None:
        path = urlparse(self.path).path
        try:
            if path == "/api/receive":
                payload = self._body()
                return self._json(self.pipeline.receive(payload["source_dir"],
                                                        self.batch_id))
            if path == "/api/validate":
                return self._json(self.pipeline.validate(self.batch_id))
            if path == "/api/publish":
                payload = self._body()
                policy = Policy(payload.get("policy", Policy.RETAIN_CLEAN_SUBSET.value))
                crash = payload.get("crash")
                return self._json(self.pipeline.publish(self.batch_id, policy, crash=crash))
            if path == "/api/resume":
                return self._json(self.pipeline.resume(self.batch_id))
            if path == "/api/rereceive":
                return self._json(self.pipeline.rereceive(self.batch_id))
            if path == "/api/fix":
                payload = self._body()
                fix = self.pipeline.fix_row(self.batch_id, payload["table"],
                                            int(payload["line_no"]), payload["updates"])
                replay = self.pipeline.replay(self.batch_id, changed=payload)
                return self._json({"fix": fix, "replay": replay})
            self._json({"error": "unknown route", "path": path}, 404)
        except Exception as exc:  # noqa: BLE001
            self._json({"error": type(exc).__name__, "detail": str(exc)}, 500)


def serve(workspace: str, source_dir: str, batch_id: str,
          host: str = "127.0.0.1", port: int = 8000) -> None:
    pipeline = PointwisePipeline(workspace)
    # make sure the batch exists (receive is idempotent; re-copy is harmless)
    if pipeline.store.get_batch(batch_id) is None:
        pipeline.receive(source_dir, batch_id)
    Handler.pipeline = pipeline
    Handler.batch_id = batch_id
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"pointwise pipeline UI: http://{host}:{port}/  (batch {batch_id})")
    print(f"workspace: {os.path.abspath(workspace)}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
        pipeline.close()
