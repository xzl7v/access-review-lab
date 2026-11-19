import json
import unittest
from pathlib import Path

from replay import assess, replay


class AccessReviewReplayTests(unittest.TestCase):
    def setUp(self):
        source = Path(__file__).resolve().parents[1] / "scenario.json"
        self.scenario = json.loads(source.read_text(encoding="utf-8"))
        self.case = self.scenario["case"]

    def test_reference_case(self):
        first, remaining, removed, partial = replay(self.scenario)["observations"]
        self.assertEqual(first["verdict"], "detected")
        self.assertEqual([path["kind"] for path in first["paths"]], ["direct", "team"])
        self.assertEqual(remaining["verdict"], "still_granted")
        self.assertEqual(remaining["paths"], [{
            "kind": "team",
            "team_id": "release-engineering",
            "evidence": [
                "/snapshots/1/sources/team_memberships/rows/0",
                "/snapshots/1/sources/team_grants/rows/0",
            ],
        }])
        self.assertEqual((removed["verdict"], removed["paths"]), ("verified_removed", []))
        self.assertEqual((partial["verdict"], partial["incomplete_sources"]),
                         ("inconclusive", ["team_memberships"]))

    def test_complete_empty_membership_is_distinct_from_missing_membership(self):
        follow_up = self.scenario["snapshots"][2]
        follow_up["sources"]["team_memberships"]["rows"] = []
        self.assertEqual(assess(self.case, follow_up, 2)["verdict"], "verified_removed")
        follow_up["sources"]["team_memberships"]["complete"] = False
        self.assertEqual(assess(self.case, follow_up, 2)["verdict"], "inconclusive")

    def test_incomplete_sources_preserve_positive_evidence(self):
        follow_up = self.scenario["snapshots"][1]
        del follow_up["sources"]["direct_grants"]
        result = assess(self.case, follow_up, 1)
        self.assertEqual(result["verdict"], "still_granted")
        self.assertEqual(result["incomplete_sources"], ["direct_grants"])

    def test_same_time_as_decision_cannot_verify_removal(self):
        follow_up = self.scenario["snapshots"][2]
        follow_up["captured_at"] = self.case["decision"]["recorded_at"]
        self.assertEqual(assess(self.case, follow_up, 2)["verdict"], "inconclusive")

    def test_scope_mismatch_cannot_verify_removal(self):
        follow_up = self.scenario["snapshots"][2]
        follow_up["repository"] = "another-repository"
        self.assertEqual(assess(self.case, follow_up, 2)["verdict"], "inconclusive")

    def test_invalid_completeness_flag_is_rejected(self):
        follow_up = self.scenario["snapshots"][2]
        follow_up["sources"]["team_memberships"]["complete"] = "true"
        with self.assertRaisesRegex(ValueError, "boolean complete flag"):
            assess(self.case, follow_up, 2)

    def test_baseline_has_to_observe_a_grant(self):
        baseline = self.scenario["snapshots"][0]
        baseline["sources"]["direct_grants"]["rows"] = []
        baseline["sources"]["team_memberships"]["rows"] = []
        with self.assertRaisesRegex(ValueError, "baseline must show a grant path"):
            replay(self.scenario)


if __name__ == "__main__":
    unittest.main()
