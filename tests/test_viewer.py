from base64 import b64decode, b64encode
from hashlib import sha256
import json
import re
import unittest

from build_demo import render_viewer


class ViewerAssetsTests(unittest.TestCase):
    def test_sample_includes_csv_record_provenance(self):
        page = render_viewer()
        encoded = re.search(r'<script type="text/plain" id="sample-packet">([A-Za-z0-9+/=]+)</script>', page)
        self.assertIsNotNone(encoded)
        packet = json.loads(b64decode(encoded.group(1)))
        self.assertEqual(packet["packet_version"], 2)
        reference = "/snapshots/1/sources/team_memberships/rows/0"
        record = packet["provenance"]["records"][reference]
        self.assertEqual(record["record_number"], 1)
        self.assertEqual(packet["provenance"]["sources"][record["source_ref"]]["file"],
                         "memberships-before.csv")
        observations = {item["snapshot"]: item for item in packet["observations"]}
        self.assertEqual(observations["both-paths-removed"]["verdict"], "verified_removed")
        for name in ("stale-membership-export", "wrong-repository-export"):
            with self.subTest(snapshot=name):
                self.assertEqual(observations[name]["verdict"], "inconclusive")
                self.assertEqual(observations[name]["source_coverage"]["team_memberships"], "invalid")

    def test_viewer_embeds_the_ordered_sample_batch(self):
        page = render_viewer()
        encoded = re.search(r'<script type="text/plain" id="sample-batch">([A-Za-z0-9+/=]+)</script>', page)
        self.assertIsNotNone(encoded)
        batch = json.loads(b64decode(encoded.group(1)))
        self.assertEqual(batch["batch_version"], 1)
        reviews = batch["reviews"]
        self.assertEqual([review["packet"]["case"]["id"] for review in reviews], ["AR-101", "AR-102", "AR-103"])
        selected = [
            next(observation["verdict"] for observation in review["packet"]["observations"]
                 if observation["snapshot"] == review["follow_up"])
            for review in reviews
        ]
        self.assertEqual(selected, ["still_granted", "inconclusive", "verified_removed"])

    def test_security_policy_matches_the_script_in_the_page(self):
        page = render_viewer()
        script = re.search(r"<script>([\s\S]+?)</script>", page)
        self.assertIsNotNone(script)
        fingerprint = b64encode(sha256(script.group(1).encode("utf-8")).digest()).decode("ascii")
        self.assertIn("default-src 'none'", page)
        self.assertIn(f"script-src 'sha256-{fingerprint}'", page)
