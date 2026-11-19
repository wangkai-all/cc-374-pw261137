"""End-to-end tests for the pointwise-restart pipeline.

Run:  python3 -I -m unittest discover -s tests -v
Uses only the standard library and the synthetic batch in data/batches.
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from pointwise import PointwisePipeline, Policy, Stage, verify_release  # noqa: E402
from pointwise.publisher import resume_publish  # noqa: E402

SOURCE = os.path.join(ROOT, "data", "batches", "BATCH-2026-ALPHA")
BATCH = "BATCH-TEST"


class PipelineTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="pw-test-")
        self.workspace = os.path.join(self.tmp, "ws")
        self.pipe = PointwisePipeline(self.workspace)
        self.pipe.receive(SOURCE, BATCH)

    def tearDown(self) -> None:
        self.pipe.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def validate(self) -> dict:
        return self.pipe.validate(BATCH)


class TestValidation(PipelineTestBase):
    def test_expected_counts_on_synthetic_batch(self):
        res = self.validate()
        stats = res["stats"]
        self.assertEqual(stats["total_rows"], 38)
        self.assertEqual(stats["per_table"]["accounts"],
                         {"total": 13, "valid": 8, "quarantined": 5,
                          "intrinsic_bad": 5, "tainted": 0})
        self.assertEqual(stats["per_table"]["relationships"]["intrinsic_bad"], 3)
        self.assertEqual(stats["per_table"]["relationships"]["tainted"], 4)
        self.assertEqual(stats["per_table"]["transactions"]["intrinsic_bad"], 4)
        self.assertEqual(stats["per_table"]["transactions"]["tainted"], 5)
        self.assertEqual(stats["missing_references"], 5)

    def test_duplicate_key_quarantines_both_rows(self):
        res = self.validate()
        dup = [r for r in res["rows"]["accounts"] if r["key"] == "ACC-1011"]
        self.assertEqual(len(dup), 2)
        self.assertTrue(all(r["status"] == "QUARANTINED" for r in dup))
        self.assertTrue(all("E_KEY_DUPLICATE" in r["intrinsic_codes"] for r in dup))

    def test_missing_primary_key_detected(self):
        res = self.validate()
        no_key = [r for r in res["rows"]["accounts"] if not r["key"]]
        self.assertEqual(len(no_key), 1)
        self.assertIn("E_KEY_MISSING", no_key[0]["intrinsic_codes"])

    def test_bad_account_referenced_by_multiple_transactions(self):
        """The headline requirement: one bad account, multiple referencing
        transactions, all captured with explicit chains."""
        res = self.validate()
        acc1002 = next(r for r in res["rows"]["accounts"] if r["key"] == "ACC-1002")
        self.assertEqual(acc1002["status"], "QUARANTINED")
        self.assertIn("E_BALANCE_NEGATIVE", acc1002["intrinsic_codes"])
        tainted_txns = [
            r for r in res["rows"]["transactions"]
            if r["taint_path"] and r["taint_path"][0]["key"] == "ACC-1002"
        ]
        self.assertEqual(sorted(r["key"] for r in tainted_txns),
                         ["T-1001", "T-1003", "T-1008"])
        for r in tainted_txns:
            self.assertEqual(r["taint_path"][0]["role"], "ROOT")
            self.assertEqual(r["taint_path"][-1]["key"], r["key"])

    def test_all_taint_chains_start_at_intrinsically_bad_row(self):
        res = self.validate()
        # root rows = quarantined rows that are NOT themselves tainted
        bad_refs = {
            f"{t}:{r['key'] or '<missing-key>'}#L{r['line_no']}"
            for t, rows in res["rows"].items()
            for r in rows
            if r["status"] == "QUARANTINED" and not r["taint_path"]
        }
        for table in res["rows"]:
            for row in res["rows"][table]:
                if row["taint_path"]:
                    root = row["taint_path"][0]
                    root_ref = (f"{root['table']}:{root['key'] or '<missing-key>'}"
                                f"#L{root['line_no']}")
                    self.assertIn(root_ref, bad_refs)
                    self.assertEqual(root["role"], "ROOT")
                    self.assertEqual(row["taint_path"][-1]["table"], table)
                    self.assertEqual(row["taint_path"][-1]["line_no"], row["line_no"])


class TestSubsetPolicyAndClosure(PipelineTestBase):
    def test_published_subset_is_referentially_closed(self):
        self.validate()
        out = self.pipe.publish(BATCH, Policy.RETAIN_CLEAN_SUBSET)
        report = verify_release(out["release_dir"])
        self.assertTrue(report["verified"])
        self.assertEqual(report["orphan_references"], [])

    def test_no_silent_drops_every_excluded_row_documented(self):
        self.validate()
        out = self.pipe.publish(BATCH, Policy.RETAIN_CLEAN_SUBSET)
        manifest = out["manifest"]
        n_pub = sum(manifest["counts"]["published"].values())
        n_quar = sum(manifest["counts"]["quarantined"].values())
        self.assertEqual(n_pub + n_quar, 38)
        for q in manifest["quarantined_rows"]:
            self.assertTrue(q["reason_codes"])
            self.assertTrue(q["remediation"])
        self.assertEqual(len(manifest["deleted_dependency_notes"]), n_quar)

    def test_quarantine_bundle_contains_all_three_tables(self):
        self.validate()
        out = self.pipe.publish(BATCH, Policy.RETAIN_CLEAN_SUBSET)
        for name in ("accounts.csv", "relationships.csv", "transactions.csv",
                     "handback-manifest.json", "CHECKSUMS.sha256"):
            self.assertTrue(os.path.isfile(os.path.join(out["quarantine_dir"], name)))

    def test_verify_detects_tampering(self):
        self.validate()
        out = self.pipe.publish(BATCH, Policy.RETAIN_CLEAN_SUBSET)
        with open(os.path.join(out["release_dir"], "accounts.csv"), "a") as fh:
            fh.write("ACC-9999,Forged,USD,1.00,ACTIVE,US\n")
        report = verify_release(out["release_dir"])
        self.assertFalse(report["verified"])
        self.assertIn("accounts.csv", report["checksum_mismatches"])


class TestRejectPolicy(PipelineTestBase):
    def test_full_rejection_publishes_nothing(self):
        self.validate()
        out = self.pipe.publish(BATCH, Policy.REJECT_BATCH)
        self.assertIn("REJECTED", out["manifest"]["outcome"])
        self.assertEqual(sum(out["manifest"]["counts"]["published"].values()), 0)
        self.assertEqual(sum(out["manifest"]["counts"]["quarantined"].values()), 38)
        report = verify_release(out["release_dir"])
        self.assertTrue(report["verified"])


class TestPointwiseReplay(PipelineTestBase):
    def test_fix_one_row_only_revalidates_affected_closure(self):
        res = self.validate()
        self.assertEqual(len(res["cache"]["misses"]), 37)  # duplicate rows share a hash

        self.pipe.fix_row(BATCH, "accounts", 2, {"balance": "315.25"})
        replay = self.pipe.replay(BATCH)

        # exactly one new content hash needs intrinsic re-validation; the
        # fixed row's old hash drops out, so 36 prior hashes hit and 1 misses
        self.assertEqual(len(replay["cache"]["misses"]), 1)
        self.assertEqual(len(replay["cache"]["hits"]), 36)
        # row count is conserved: 36 hits + 1 miss + the duplicate row that
        # shares the fixed row's new hash is covered within the same miss hash
        self.assertEqual(len(replay["cache"]["hits"]) +
                         len(replay["cache"]["misses"]), 37)
        # replay scope = fixed row + its transitive dependents (6 rows)
        self.assertEqual(replay["replay"]["replayed_count"], 6)
        self.assertEqual(replay["replay"]["reused_count"], 32)
        scope = {(r["table"], r["line_no"]) for r in replay["replay"]["replayed_rows"]}
        self.assertIn(("accounts", 2), scope)
        self.assertIn(("transactions", 1), scope)   # T-1001
        self.assertIn(("transactions", 3), scope)   # T-1003
        self.assertIn(("transactions", 8), scope)   # T-1008

        post_acc = {r["key"]: r for r in replay["rows"]["accounts"]}
        self.assertEqual(post_acc["ACC-1002"]["status"], "VALID")
        post_txn = {r["key"]: r for r in replay["rows"]["transactions"]}
        self.assertEqual(post_txn["T-1001"]["status"], "VALID")
        self.assertEqual(post_txn["T-1003"]["status"], "VALID")

    def test_replay_without_fix_is_all_cache_hits(self):
        self.validate()
        replay = self.pipe.replay(BATCH)
        self.assertEqual(len(replay["cache"]["misses"]), 0)
        self.assertGreater(len(replay["cache"]["hits"]), 0)

    def test_new_release_after_fix_is_immutable_new_version(self):
        self.validate()
        v1 = self.pipe.publish(BATCH, Policy.RETAIN_CLEAN_SUBSET)
        self.pipe.fix_row(BATCH, "accounts", 2, {"balance": "315.25"})
        self.pipe.replay(BATCH)
        v2 = self.pipe.publish(BATCH, Policy.RETAIN_CLEAN_SUBSET)
        self.assertEqual(v2["version"], v1["version"] + 1)
        self.assertTrue(os.path.isdir(v1["release_dir"]))  # v1 untouched
        self.assertNotEqual(v1["release_dir"], v2["release_dir"])


class TestCrashRecovery(PipelineTestBase):
    def test_crash_after_validate_before_publish_resumes_without_revalidation(self):
        self.validate()
        crash = self.pipe.publish(BATCH, Policy.RETAIN_CLEAN_SUBSET,
                                  crash="pre_publish")
        self.assertEqual(crash["stage"], Stage.CRASHED_PRE_PUBLISH.value)
        self.assertEqual(self.pipe.status(BATCH)["stage"],
                         Stage.CRASHED_PRE_PUBLISH.value)
        rec = self.pipe.resume(BATCH)
        self.assertEqual(rec["recovered_from"], Stage.CRASHED_PRE_PUBLISH.value)
        self.assertTrue(verify_release(rec["release_dir"])["verified"])
        self.assertEqual(self.pipe.status(BATCH)["stage"], Stage.PUBLISHED.value)

    def test_crash_during_publish_leaves_no_partial_release(self):
        self.validate()
        crash = self.pipe.publish(BATCH, Policy.RETAIN_CLEAN_SUBSET,
                                  crash="mid_publish")
        version = crash["version"]
        releases = os.path.join(self.workspace, "releases")
        self.assertFalse(os.path.isdir(os.path.join(releases, f"v{version}")))
        self.assertTrue(os.path.isdir(
            os.path.join(self.workspace, "staging", f"release-v{version}")))

        rec = self.pipe.resume(BATCH)
        self.assertTrue(rec["recovered"])
        self.assertTrue(verify_release(rec["release_dir"])["verified"])
        self.assertFalse(os.path.isdir(
            os.path.join(self.workspace, "staging", f"release-v{version}")))

    def test_resume_is_idempotent(self):
        self.validate()
        self.pipe.publish(BATCH, Policy.RETAIN_CLEAN_SUBSET, crash="mid_publish")
        first = self.pipe.resume(BATCH)
        second = self.pipe.resume(BATCH)
        self.assertTrue(first["recovered"])
        self.assertFalse(second.get("recovered"))

    def test_resume_rejects_corrupt_staging(self):
        self.validate()
        crash = self.pipe.publish(BATCH, Policy.RETAIN_CLEAN_SUBSET,
                                  crash="mid_publish")
        with open(os.path.join(crash["staging_release"], "accounts.csv"),
                  "a") as fh:
            fh.write("tampered\n")
        with self.assertRaises(RuntimeError):
            resume_publish(self.workspace, crash["version"])


class TestChecksumsAndZips(PipelineTestBase):
    def test_both_zips_downloadable_and_consistent(self):
        import zipfile
        self.validate()
        out = self.pipe.publish(BATCH, Policy.RETAIN_CLEAN_SUBSET)
        for zip_path in (out["release_zip"], out["quarantine_zip"]):
            self.assertTrue(os.path.isfile(zip_path))
            with zipfile.ZipFile(zip_path) as zf:
                self.assertIn("CHECKSUMS.sha256", zf.namelist())
                self.assertIsNone(zf.testzip())

    def test_source_files_never_mutated(self):
        from pointwise.loader import sha256_file
        before = {f: sha256_file(os.path.join(SOURCE, f))
                  for f in os.listdir(SOURCE) if f.endswith(".csv")}
        self.validate()
        self.pipe.fix_row(BATCH, "accounts", 2, {"balance": "9.99"})
        self.pipe.replay(BATCH)
        after = {f: sha256_file(os.path.join(SOURCE, f))
                 for f in os.listdir(SOURCE) if f.endswith(".csv")}
        self.assertEqual(before, after)


class TestQueryAndRereceive(PipelineTestBase):
    def test_query_returns_status_chain_and_reverse_closure(self):
        self.validate()
        q = self.pipe.query_row(BATCH, "ACC-1002")
        self.assertTrue(q["found"])
        self.assertEqual(len(q["matches"]), 1)
        m = q["matches"][0]
        self.assertEqual(m["table"], "accounts")
        self.assertEqual(m["status"], "QUARANTINED")
        self.assertIn("E_BALANCE_NEGATIVE", m["intrinsic_codes"])
        # the three transactions plus two relationships referencing ACC-1002
        # are all inside the reported fix-impact closure
        closure = {(c["table"], c["key"]) for c in m["reverse_closure"]}
        self.assertIn(("transactions", "T-1001"), closure)
        self.assertIn(("transactions", "T-1003"), closure)
        self.assertIn(("transactions", "T-1008"), closure)
        self.assertEqual(m["reverse_closure_count"], len(closure))

    def test_query_unknown_key(self):
        self.validate()
        q = self.pipe.query_row(BATCH, "ACC-DOES-NOT-EXIST")
        self.assertFalse(q["found"])

    def test_query_duplicate_key_returns_both_rows(self):
        self.validate()
        q = self.pipe.query_row(BATCH, "ACC-1011")
        self.assertTrue(q["found"])
        self.assertEqual(len(q["matches"]), 2)
        self.assertTrue(all(m["status"] == "QUARANTINED" for m in q["matches"]))

    def test_rereceive_restores_working_copy_after_fix(self):
        self.validate()
        self.pipe.fix_row(BATCH, "accounts", 2, {"balance": "315.25"})
        replay = self.pipe.replay(BATCH)
        acc = next(r for r in replay["rows"]["accounts"] if r["key"] == "ACC-1002")
        self.assertEqual(acc["values"]["balance"], "315.25")

        out = self.pipe.rereceive(BATCH)
        self.assertEqual(self.pipe.status(BATCH)["stage"], "RECEIVED")
        loaded = self.pipe._load(BATCH)
        acc = next(r for r in loaded.rows["accounts"] if r.key == "ACC-1002")
        self.assertEqual(acc.values["balance"], "-875.50")  # back to source value
        self.assertIn("rows", out)

    def test_rereceive_keeps_published_releases(self):
        self.validate()
        v1 = self.pipe.publish(BATCH, Policy.RETAIN_CLEAN_SUBSET)
        self.pipe.fix_row(BATCH, "accounts", 2, {"balance": "315.25"})
        self.pipe.rereceive(BATCH)
        self.assertTrue(os.path.isdir(v1["release_dir"]))
        self.assertEqual(len(self.pipe.status(BATCH)["releases"]), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
