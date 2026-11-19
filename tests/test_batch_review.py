import json
from pathlib import Path
import re
from shutil import copytree
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

from evidence import build_packet, load_json

ROOT = Path(__file__).resolve().parents[1]


class BatchReviewTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.inputs = self.directory / "inputs"
        copytree(ROOT / "examples" / "batch", self.inputs)
        self.manifest = self.inputs / "manifest.json"
        self.output = self.directory / "review"

    def write_manifest(self, entries):
        self.manifest.write_text(json.dumps({"cases": entries}), encoding="utf-8")

    def run_batch(self, *options):
        return subprocess.run(
            [sys.executable, "-B", str(ROOT / "batch_review.py"),
             str(self.manifest), "--output", str(self.output), *options],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_report_prioritizes_cases_and_links_complete_packets(self):
        result = self.run_batch()
        self.assertEqual(result.returncode, 0, result.stderr)
        report = (self.output / "report.md").read_text(encoding="utf-8")
        self.assertIn("3 cases. 1 still granted, 1 needs evidence, 1 verified removed.", report)
        batch = load_json(self.output / "batch.json")
        self.assertEqual(batch["batch_version"], 1)
        self.assertEqual(len(batch["reviews"]), 3)
        rows = [line for line in report.splitlines() if line.startswith("| AR-")]
        self.assertEqual(len(rows), 3)
        expected = (
            ("AR-101", "Still granted", "still-granted.json"),
            ("AR-102", "Needs evidence", "needs-evidence.json"),
            ("AR-103", "Verified removed", "verified-removed.json"),
        )
        for row, (case_id, verdict, example), review in zip(rows, expected, batch["reviews"]):
            self.assertIn(f"| {case_id} |", row)
            self.assertIn(f"| {verdict} |", row)
            link = re.search(r"\[Packet\]\((evidence/\d+\.json)\)", row)
            self.assertIsNotNone(link)
            packet = load_json(self.output / link.group(1))
            self.assertEqual(packet, build_packet(load_json(self.inputs / example)))
            self.assertEqual(review, {"follow_up": packet["observations"][1]["snapshot"], "packet": packet})
        self.assertIn("Team grant via release-engineering", rows[0])
        self.assertIn("membership-export-missing", rows[1])

    def test_batch_accepts_csv_with_an_explicit_follow_up(self):
        copytree(ROOT / "examples" / "csv", self.inputs / "csv")
        self.write_manifest([
            {"scenario": "verified-removed.json"},
            {"exports": "csv/manifest.json", "follow_up": "direct-grant-removed"},
        ])
        result = self.run_batch()
        self.assertEqual(result.returncode, 0, result.stderr)
        report = (self.output / "report.md").read_text(encoding="utf-8")
        self.assertRegex(report, r"\| AR-001 \|.*direct-grant-removed.*\| Still granted \|")
        self.assertEqual(load_json(self.output / "evidence" / "001.json"),
                         load_json(ROOT / "docs" / "evidence.json"))

    def test_mixed_batch_writes_provenance_for_csv_packets(self):
        copytree(ROOT / "examples" / "csv", self.inputs / "csv")
        self.write_manifest([
            {"scenario": "verified-removed.json"},
            {"exports": "csv/manifest.json", "follow_up": "direct-grant-removed"},
        ])
        result = self.run_batch("--provenance")
        self.assertEqual(result.returncode, 0, result.stderr)
        csv_packet = load_json(self.output / "evidence" / "001.json")
        self.assertEqual(csv_packet["packet_version"], 2)
        browser_file = load_json(self.output / "batch.json")
        self.assertEqual(browser_file["reviews"][0],
                         {"follow_up": "direct-grant-removed", "packet": csv_packet})
        source = "/snapshots/1/sources/team_memberships"
        self.assertEqual(csv_packet["provenance"]["sources"][source]["file"], "memberships-before.csv")
        self.assertEqual(csv_packet["provenance"]["records"][source + "/rows/0"]["record_number"], 1)
        json_packet = load_json(self.output / "evidence" / "002.json")
        self.assertEqual(json_packet, build_packet(load_json(self.inputs / "verified-removed.json")))

    def test_capture_failure_is_in_the_report_and_batch_file(self):
        copytree(ROOT / "examples" / "csv", self.inputs / "csv")
        self.write_manifest([{"exports": "csv/checked-manifest.json", "follow_up": "stale-membership-export"}])
        result = self.run_batch("--provenance")
        self.assertEqual(result.returncode, 0, result.stderr)
        report = (self.output / "report.md").read_text(encoding="utf-8")
        self.assertIn("| Needs evidence |", report)
        self.assertIn("memberships-after.csv", report)
        self.assertIn("differs from snapshot time", report)
        review, = load_json(self.output / "batch.json")["reviews"]
        observation = next(item for item in review["packet"]["observations"] if item["snapshot"] == review["follow_up"])
        self.assertEqual(observation["source_coverage"]["team_memberships"], "invalid")

    def test_multiple_follow_ups_require_a_valid_selection(self):
        copytree(ROOT / "examples" / "csv", self.inputs / "csv")
        for selection, error in (
            ({}, "has multiple follow-ups"),
            ({"follow_up": "before-decision"}, "is not a follow-up snapshot"),
        ):
            with self.subTest(selection=selection):
                self.write_manifest([{"exports": "csv/manifest.json", **selection}])
                result = self.run_batch()
                self.assertEqual(result.returncode, 2)
                self.assertIn(error, result.stderr)
                self.assertFalse(self.output.exists())

    def test_invalid_later_input_does_not_publish_a_partial_batch(self):
        self.write_manifest([{"scenario": "still-granted.json"}, {"scenario": "missing.json"}])
        result = self.run_batch()
        self.assertEqual(result.returncode, 2)
        self.assertIn("case input is unavailable: missing.json", result.stderr)
        self.assertFalse(self.output.exists())

    def test_repeated_case_ids_are_rejected(self):
        self.write_manifest([{"scenario": "still-granted.json"}] * 2)
        result = self.run_batch()
        self.assertEqual(result.returncode, 2)
        self.assertIn("duplicate case ID: AR-101", result.stderr)
        self.assertFalse(self.output.exists())

    def test_existing_report_is_preserved_on_retry(self):
        result = self.run_batch()
        self.assertEqual(result.returncode, 0, result.stderr)
        original = {path.relative_to(self.output): path.read_bytes()
                    for path in self.output.rglob("*") if path.is_file()}
        retry = self.run_batch()
        self.assertEqual(retry.returncode, 2)
        self.assertIn("output path already exists", retry.stderr)
        self.assertEqual({path.relative_to(self.output): path.read_bytes()
                          for path in self.output.rglob("*") if path.is_file()}, original)

    def test_report_escapes_fields_that_could_change_the_table(self):
        case = self.inputs / "still-granted.json"
        scenario = load_json(case)
        scenario["case"]["id"] = "AR|<sample>\ncase"
        case.write_text(json.dumps(scenario), encoding="utf-8")
        self.write_manifest([{"scenario": case.name}])
        result = self.run_batch()
        self.assertEqual(result.returncode, 0, result.stderr)
        report = (self.output / "report.md").read_text(encoding="utf-8")
        self.assertIn("| AR&#124;&#60;sample&#62; case |", report)
        self.assertIn("1 case.", report)
        self.assertNotIn("<sample>", report)
