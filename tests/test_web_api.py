"""HTTP-level tests for the web API (standard library only)."""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import threading
import unittest
import urllib.request
from http.server import ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from pointwise.models import Policy  # noqa: E402
from pointwise.web import Handler  # noqa: E402
from pointwise.pipeline import PointwisePipeline  # noqa: E402

SOURCE = os.path.join(ROOT, "data", "batches", "BATCH-2026-ALPHA")
BATCH = "BATCH-WEB"


class WebApiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp(prefix="pw-web-")
        cls.workspace = os.path.join(cls.tmp, "ws")
        cls.pipeline = PointwisePipeline(cls.workspace)
        cls.pipeline.receive(SOURCE, BATCH)
        Handler.pipeline = cls.pipeline
        Handler.batch_id = BATCH
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.pipeline.close()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _get(self, path: str):
        with urllib.request.urlopen(self.base + path, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode())

    def _post(self, path: str, payload: dict | None = None):
        data = json.dumps(payload or {}).encode()
        req = urllib.request.Request(
            self.base + path, data=data,
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode())

    def test_index_served(self):
        with urllib.request.urlopen(self.base + "/", timeout=10) as resp:
            self.assertEqual(resp.status, 200)
            self.assertIn(b"Pointwise-Restart", resp.read())

    def _get_raw(self, path: str):
        with urllib.request.urlopen(self.base + path, timeout=10) as resp:
            return resp.status, resp.read(), resp.headers.get("Content-Type")

    def test_validate_publish_download_chain(self):
        _, validation = self._post("/api/validate")
        self.assertEqual(validation["stats"]["total_rows"], 38)
        _, out = self._post("/api/publish",
                            {"policy": Policy.RETAIN_CLEAN_SUBSET.value})
        version = out["version"]
        import zipfile
        import io
        for name in (f"release-v{version}.zip", f"quarantine-v{version}.zip"):
            status, body, ctype = self._get_raw(f"/api/download?file={name}")
            self.assertEqual(status, 200)
            self.assertEqual(ctype, "application/zip")
            with zipfile.ZipFile(io.BytesIO(body)) as zf:
                self.assertIn("CHECKSUMS.sha256", zf.namelist())

    def test_path_traversal_rejected(self):
        from urllib.error import HTTPError
        with self.assertRaises(HTTPError) as ctx:
            self._get("/api/download?file=../pipeline.db")
        self.assertEqual(ctx.exception.code, 404)

    def test_web_fix_and_replay_scope(self):
        self._post("/api/validate")
        _, data = self._post("/api/fix", {
            "table": "accounts", "line_no": 2,
            "updates": {"balance": "315.25"}})
        replay = data["replay"]["replay"]
        self.assertEqual(replay["replayed_count"], 6)
        self.assertEqual(replay["reused_count"], 32)

    def test_crash_resume_over_http(self):
        self._post("/api/validate")
        _, crash = self._post("/api/publish",
                              {"policy": "retain_subset", "crash": "pre_publish"})
        self.assertEqual(crash["stage"], "CRASHED_PRE_PUBLISH")
        _, status = self._get("/api/status")
        self.assertEqual(status["stage"], "CRASHED_PRE_PUBLISH")
        _, rec = self._post("/api/resume")
        self.assertEqual(rec["recovered_from"], "CRASHED_PRE_PUBLISH")
        _, status = self._get("/api/status")
        self.assertEqual(status["stage"], "PUBLISHED")

    def test_manifest_endpoint(self):
        self._post("/api/validate")
        _, out = self._post("/api/publish", {"policy": "reject_batch"})
        _, manifest = self._get(
            f"/api/manifest?version={out['version']}&kind=quarantine")
        self.assertEqual(sum(manifest["counts"]["published"].values()), 0)
        self.assertEqual(sum(manifest["counts"]["quarantined"].values()), 38)

    def test_query_endpoint_impact_closure(self):
        self._post("/api/validate")
        _, q = self._get("/api/query?key=ACC-1002")
        self.assertTrue(q["found"])
        m = q["matches"][0]
        keys = {c["key"] for c in m["reverse_closure"]
                if c["table"] == "transactions"}
        self.assertEqual(keys, {"T-1001", "T-1003", "T-1008"})

    def test_query_missing_key_param(self):
        from urllib.error import HTTPError
        with self.assertRaises(HTTPError) as ctx:
            self._get("/api/query")
        self.assertEqual(ctx.exception.code, 400)

    def test_rereceive_endpoint_restores_working_copy(self):
        self._post("/api/validate")
        self._post("/api/fix", {"table": "accounts", "line_no": 2,
                                "updates": {"balance": "315.25"}})
        _, out = self._post("/api/rereceive")
        self.assertEqual(out["rows"]["accounts"], 13)
        _, validation = self._post("/api/validate")
        acc = next(r for r in validation["rows"]["accounts"]
                   if r["key"] == "ACC-1002")
        self.assertEqual(acc["values"]["balance"], "-875.50")


if __name__ == "__main__":
    unittest.main(verbosity=2)
