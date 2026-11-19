import json
from pathlib import Path
from shutil import copytree
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

from csv_exports import load_csv_exports
from evidence import build_packet, load_json

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "csv"


class CsvExportTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.exports = self.directory / "exports"
        copytree(EXAMPLE, self.exports)
        self.manifest = self.exports / "manifest.json"
        self.data = load_json(self.manifest)

    def write_manifest(self):
        self.manifest.write_text(json.dumps(self.data), encoding="utf-8")

    def run_replay(self, *options):
        return subprocess.run(
            [sys.executable, "-B", str(ROOT / "replay.py"), "--exports", str(self.manifest), *options],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_sample_reproduces_the_published_packet(self):
        published = ROOT / "docs" / "evidence.json"
        result = self.run_replay("--verify", str(published), "--json")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, published.read_text(encoding="utf-8"))

    def test_columns_can_be_reordered_and_include_extra_fields(self):
        source = self.exports / "direct-before.csv"
        export = ('role,notes,repository,account_id\r\n'
                  'Admin,"included in export, reviewed",release-runbooks,A-202\r\n')
        source.write_bytes(export.encode("utf-8-sig"))
        scenario, _ = load_csv_exports(self.manifest)
        self.assertEqual(scenario, load_json(ROOT / "scenario.json"))

    def test_partial_membership_export_cannot_verify_removal(self):
        self.data["snapshots"][2]["sources"]["team_memberships"]["complete"] = False
        self.write_manifest()
        scenario, _ = load_csv_exports(self.manifest)
        follow_up = build_packet(scenario)["observations"][2]
        self.assertEqual(follow_up["verdict"], "inconclusive")
        self.assertEqual(follow_up["source_coverage"]["team_memberships"], "partial")

    def test_nested_team_link_is_included_in_the_evidence(self):
        self.data["case"]["team_model"] = "nested"
        (self.exports / "memberships-before.csv").write_text(
            "account_id,team_id\nA-202,release-operators\n", encoding="utf-8"
        )
        (self.exports / "links.csv").write_text(
            "child_team_id,parent_team_id\nrelease-operators,release-engineering\n", encoding="utf-8"
        )
        for snapshot in self.data["snapshots"]:
            snapshot["sources"]["team_links"] = {"file": "links.csv", "complete": True}
        self.write_manifest()
        scenario, _ = load_csv_exports(self.manifest)
        packet = build_packet(scenario)
        follow_up = packet["observations"][1]
        reference = "/snapshots/1/sources/team_links/rows/0"
        self.assertEqual(follow_up["verdict"], "still_granted")
        self.assertIn(reference, follow_up["paths"][0]["evidence"])
        self.assertEqual(packet["evidence"][reference]["parent_team_id"], "release-engineering")

    def test_declared_export_must_exist_before_writing_output(self):
        self.data["snapshots"][2]["sources"]["team_memberships"]["file"] = "unavailable.csv"
        self.write_manifest()
        output = self.directory / "packet.json"
        result = self.run_replay("--output", str(output))
        self.assertEqual(result.returncode, 2)
        self.assertIn("CSV export is unavailable: unavailable.csv", result.stderr)
        self.assertFalse(output.exists())

    def test_manifest_cannot_reference_a_file_outside_its_directory(self):
        outside = self.directory / "outside.csv"
        outside.write_text("account_id,repository,role\nA-202,release-runbooks,Admin\n", encoding="utf-8")
        self.data["snapshots"][0]["sources"]["direct_grants"]["file"] = "../outside.csv"
        self.write_manifest()
        with self.assertRaisesRegex(ValueError, "inside the manifest directory"):
            load_csv_exports(self.manifest)

    def test_malformed_csv_rows_and_headers_are_rejected(self):
        source = self.exports / "direct-before.csv"
        cases = (
            ("account_id,repository\n", "missing CSV columns"),
            ("account_id,repository,role,role\n", "unique column names"),
            ("account_id,repository,role\nA-202,release-runbooks\n", "different field count"),
            ("account_id,repository,role\nA-202,release-runbooks,Admin,extra\n", "different field count"),
            ('account_id,repository,role\nA-202,release-runbooks,"Admin\n', "invalid CSV"),
        )
        for content, error in cases:
            with self.subTest(error=error):
                source.write_text(content, encoding="utf-8")
                with self.assertRaisesRegex(ValueError, error):
                    load_csv_exports(self.manifest)

    def test_output_cannot_overwrite_a_csv_source(self):
        source = self.exports / "direct-before.csv"
        original = source.read_bytes()
        result = self.run_replay("--output", str(source))
        self.assertEqual(result.returncode, 2)
        self.assertIn("CSV exports, output", result.stderr)
        self.assertEqual(source.read_bytes(), original)
