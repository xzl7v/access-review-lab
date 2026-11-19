import copy
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

from evidence import build_packet, digest, load_json, resolve_pointer
from ledger import record_review
from review import assess, replay

ROOT = Path(__file__).resolve().parents[1]


class ReleaseChecks(unittest.TestCase):
    def setUp(self):
        self.scenario = json.loads((ROOT / "scenario.json").read_text(encoding="utf-8"))
        self.case = self.scenario["case"]

    def nested_follow_up(self):
        self.case["team_model"] = "nested"
        snapshot = self.scenario["snapshots"][1]
        snapshot["sources"]["team_memberships"]["rows"][0]["team_id"] = "delivery-operators"
        snapshot["sources"]["team_links"] = {
            "complete": True,
            "rows": [{"child_team_id": "delivery-operators", "parent_team_id": "release-engineering"}],
        }
        return snapshot

    def test_nested_access_path_preserves_evidence_chain(self):
        report = assess(self.case, self.nested_follow_up(), 1)
        self.assertEqual(report["verdict"], "still_granted")
        [path] = report["paths"]
        self.assertEqual(path["evidence"], [
            "/snapshots/1/sources/team_memberships/rows/0",
            "/snapshots/1/sources/team_links/rows/0",
            "/snapshots/1/sources/team_grants/rows/0",
        ])

    def test_missing_nested_source_cannot_verify_absence(self):
        snapshot = self.nested_follow_up()
        del snapshot["sources"]["team_links"]
        report = assess(self.case, snapshot, 1)
        self.assertEqual(report["verdict"], "inconclusive")
        self.assertEqual(report["source_coverage"]["team_links"], "missing")

    def test_team_cycle_is_rejected(self):
        snapshot = self.nested_follow_up()
        snapshot["sources"]["team_links"]["rows"].append(
            {"child_team_id": "release-engineering", "parent_team_id": "delivery-operators"}
        )
        with self.assertRaisesRegex(ValueError, "team_links contains a cycle"):
            assess(self.case, snapshot, 1)

    def test_duplicate_snapshots_are_rejected(self):
        self.scenario["snapshots"].append(copy.deepcopy(self.scenario["snapshots"][1]))
        with self.assertRaisesRegex(ValueError, "snapshot IDs must be unique"):
            replay(self.scenario)

    def test_packet_reproduces_all_refs(self):
        actual = build_packet(self.scenario)
        self.assertEqual(actual, build_packet(self.scenario))
        self.assertEqual(actual["input_sha256"], digest(self.scenario))
        for ref, value in actual["evidence"].items():
            self.assertEqual(value, resolve_pointer(self.scenario, ref))
        self.assertEqual(actual["observations"][3]["source_coverage"]["team_memberships"], "missing")

    def test_ledger_retries_preserve_single_event(self):
        packet = build_packet(self.scenario)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "reviews.sqlite"
            record_review(path, packet)
            record_review(path, packet)
            with closing(sqlite3.connect(path)) as connection:
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM decisions").fetchone(), (1,))
                [stored] = connection.execute("SELECT packet_json FROM evidence_packets").fetchone()
                self.assertEqual(json.loads(stored), packet)

    def test_concurrent_ledger_writes_are_idempotent(self):
        packet = build_packet(self.scenario)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "reviews.sqlite"
            with ThreadPoolExecutor(max_workers=3) as workers:
                list(workers.map(lambda _: record_review(path, packet), range(6)))
            with closing(sqlite3.connect(path)) as connection:
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM decisions").fetchone(), (1,))
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM evidence_packets").fetchone(), (1,))

    def test_conflicting_json_keys_are_rejected_before_replay(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "snapshot.json"
            path.write_text('{"scope":{"complete":false,"complete":true}}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "'complete'"):
                load_json(path)

    def test_ledger_rejects_conflicting_decision_and_keeps_existing_record(self):
        packet = build_packet(self.scenario)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "reviews.sqlite"
            record_review(path, packet)
            self.case["decision"]["reason"] = "A different review"
            with self.assertRaisesRegex(ValueError, "different decision"):
                record_review(path, build_packet(self.scenario))
            with closing(sqlite3.connect(path)) as connection:
                [stored] = connection.execute("SELECT case_json FROM decisions").fetchone()
                self.assertEqual(json.loads(stored), packet["case"])
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM evidence_packets").fetchone(), (1,))

    def test_verify_cli_rejects_a_changed_verdict(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "evidence.json"
            args = [sys.executable, "-B", str(ROOT / "replay.py")]
            subprocess.run(args + ["--output", str(path)], capture_output=True, check=True)
            self.assertEqual(subprocess.run(args + ["--verify", str(path)], capture_output=True).returncode, 0)
            packet = json.loads(path.read_text(encoding="utf-8"))
            packet["observations"][-1]["verdict"] = "verified_removed"
            path.write_text(json.dumps(packet), encoding="utf-8")
            changed = subprocess.run(args + ["--verify", str(path)], capture_output=True, text=True)
            self.assertEqual(changed.returncode, 2)
            self.assertIn("does not match", changed.stderr)


if __name__ == "__main__":
    unittest.main()
