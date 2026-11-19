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

    def test_security_policy_matches_the_script_in_the_page(self):
        page = render_viewer()
        script = re.search(r"<script>([\s\S]+?)</script>", page)
        self.assertIsNotNone(script)
        fingerprint = b64encode(sha256(script.group(1).encode("utf-8")).digest()).decode("ascii")
        self.assertIn("default-src 'none'", page)
        self.assertIn(f"script-src 'sha256-{fingerprint}'", page)
