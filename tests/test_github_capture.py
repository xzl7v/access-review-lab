from datetime import datetime, timedelta, timezone
from hashlib import sha256
from io import BytesIO, StringIO
import json
from pathlib import Path
from shutil import copytree
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError

from evidence import build_packet, load_json, pretty_json
from github_access import API_VERSION, SOURCE, capture_role, effective_role
from github_capture import load_github_review, main as capture_command

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "github"
REPOSITORY = "example-org/release-runbooks"
ACCOUNT = "review-subject-demo"


def response(payload, request_id):
    stream = BytesIO(json.dumps(payload).encode("utf-8"))
    stream.status = 200
    stream.headers = {"X-GitHub-Request-Id": request_id}
    return stream


class GitHubCaptureTests(unittest.TestCase):
    def test_capture_uses_get_and_keeps_only_evidence_fields(self):
        token = "test-token"
        opener = Mock()
        opener.open.side_effect = [
            response({"id": 55001, "full_name": REPOSITORY, "temp_clone_token": "omit-this"}, "REPO:1"),
            response({"permission": "write", "role_name": "maintain",
                      "user": {"id": 71001, "login": ACCOUNT, "email": "omit-this"}}, "ROLE:2"),
        ]
        with patch("github_access.build_opener", return_value=opener):
            capture = capture_role(REPOSITORY, ACCOUNT, token)
        requests = [call.args[0] for call in opener.open.call_args_list]
        self.assertEqual([request.get_method() for request in requests], ["GET", "GET"])
        self.assertEqual([request.full_url for request in requests], [
            f"https://api.github.com/repos/{REPOSITORY}",
            f"https://api.github.com/repos/{REPOSITORY}/collaborators/{ACCOUNT}/permission",
        ])
        self.assertTrue(all(request.get_header("Authorization") == f"Bearer {token}" for request in requests))
        self.assertTrue(all(request.get_header("X-github-api-version") == API_VERSION for request in requests))
        self.assertNotIn(token, pretty_json(capture))
        self.assertNotIn("omit-this", pretty_json(capture))
        self.assertEqual(capture["role_lookup"]["request_id"], "ROLE:2")
        self.assertEqual(effective_role(capture).role_name, "maintain")
        self.assertLessEqual(capture["started_at"], capture["captured_at"])

    def test_explicit_none_without_embedded_user_resolves_the_account(self):
        opener = Mock()
        opener.open.side_effect = [
            response({"id": 55001, "full_name": REPOSITORY}, "REPO:1"),
            response({"permission": "none", "role_name": "none", "user": None}, "ROLE:2"),
            response({"id": 71001, "login": ACCOUNT, "email": "omit-this"}, "USER:3"),
        ]
        with patch("github_access.build_opener", return_value=opener):
            capture = capture_role(REPOSITORY, ACCOUNT, "test-token")
        self.assertEqual(opener.open.call_args.args[0].full_url, f"https://api.github.com/users/{ACCOUNT}")
        self.assertEqual(effective_role(capture).user_id, 71001)
        self.assertEqual(effective_role(capture).permission, "none")
        self.assertNotIn("omit-this", pretty_json(capture))

    def test_capture_commands_produce_replayable_offboarding_evidence(self):
        repository = {"id": 55001, "full_name": REPOSITORY}
        account = {"id": 71001, "login": ACCOUNT}
        opener = Mock()
        opener.open.side_effect = [
            response(repository, "TEST:BEFORE:REPO"),
            response({"permission": "write", "role_name": "write", "user": account}, "TEST:BEFORE:ROLE"),
            response(repository, "TEST:AFTER:REPO"),
            response({"permission": "none", "role_name": "none", "user": None}, "TEST:AFTER:ROLE"),
            response(account, "TEST:AFTER:USER"),
        ]
        decision_time = datetime(2026, 11, 20, 7, 35, tzinfo=timezone.utc)
        with TemporaryDirectory() as root:
            directory = Path(root)
            snapshots = [{"id": stage, "file": f"{stage}.json"} for stage in ("baseline", "follow-up")]
            with (patch("github_access.build_opener", return_value=opener),
                  patch("github_access.datetime") as clock,
                  patch.dict("os.environ", {"GITHUB_TOKEN": "test-token"}),
                  patch("sys.stdout", StringIO())):
                clock.now.side_effect = [decision_time + timedelta(seconds=offset)
                                         for offset in (-120, -119, 60, 61)]
                for snapshot in snapshots:
                    args = ["github_capture.py", "--repository", REPOSITORY, "--account", ACCOUNT,
                            "--output", str(directory / snapshot["file"])]
                    with patch("sys.argv", args):
                        self.assertEqual(capture_command(), 0)

            manifest = directory / "manifest.json"
            manifest.write_text(pretty_json({
                "case": {
                    "id": "GH-TEST",
                    "employee_id": "E-TEST",
                    "employee_end_at": (decision_time - timedelta(minutes=5)).isoformat(),
                    "decision": {
                        "action": "revoke_role",
                        "recorded_at": decision_time.isoformat(),
                        "reviewer": "Identity Operations",
                        "reason": "Remove the test collaborator's repository access.",
                    },
                },
                "snapshots": snapshots,
            }), encoding="utf-8")
            packet = directory / "packet.json"
            command = [sys.executable, "-B", str(ROOT / "replay.py"), "--github", str(manifest)]
            written = subprocess.run([*command, "--output", str(packet)], capture_output=True, text=True)
            self.assertEqual(written.returncode, 0, written.stderr)
            self.assertEqual(
                [(item["verdict"], item["effective_role"]) for item in load_json(packet)["observations"]],
                [("detected", "write"), ("verified_removed", "none")],
            )
            verified = subprocess.run([*command, "--verify", str(packet)], capture_output=True, text=True)
            self.assertEqual(verified.returncode, 0, verified.stderr)

    def test_http_error_saves_a_receipt_and_exits_nonzero(self):
        opener = Mock()
        opener.open.side_effect = [
            response({"id": 55001, "full_name": REPOSITORY}, "REPO:1"),
            HTTPError(f"https://api.github.com/repos/{REPOSITORY}", 403, "Forbidden",
                      {"X-GitHub-Request-Id": "ROLE:2"}, BytesIO(b"Discard response detail")),
        ]
        with TemporaryDirectory() as root:
            output = Path(root) / "denied.json"
            arguments = ["github_capture.py", "--repository", REPOSITORY, "--account", ACCOUNT,
                         "--output", str(output)]
            with (patch("github_access.build_opener", return_value=opener),
                  patch("sys.argv", arguments),
                  patch.dict("os.environ", {"GITHUB_TOKEN": "test-token"}),
                  patch("sys.stdout", StringIO()), patch("sys.stderr", StringIO()) as stderr):
                with self.assertRaises(SystemExit) as error:
                    capture_command()
            self.assertEqual(error.exception.code, 2)
            self.assertIn("HTTP 403", stderr.getvalue())
            capture = load_json(output)
            self.assertEqual(capture["role_lookup"], {"status": 403, "request_id": "ROLE:2"})

    def test_invalid_target_or_existing_output_never_replaces_evidence(self):
        with patch("github_access.build_opener") as opener:
            with self.assertRaisesRegex(ValueError, "OWNER/REPO"):
                capture_role("https://api.github.com/owner/repo", ACCOUNT, "test-token")
            opener.assert_not_called()
        with TemporaryDirectory() as root:
            output = Path(root) / "baseline.json"
            original = (EXAMPLE / "baseline.json").read_bytes()
            output.write_bytes(original)
            arguments = ["github_capture.py", "--repository", REPOSITORY, "--account", ACCOUNT,
                         "--output", str(output)]
            with (patch("github_capture.capture_role", return_value=load_json(EXAMPLE / "role-reduced.json")),
                  patch("sys.argv", arguments), patch("sys.stderr", StringIO())):
                with self.assertRaises(SystemExit) as error:
                    capture_command()
            self.assertEqual(error.exception.code, 2)
            self.assertEqual(output.read_bytes(), original)


class GitHubReviewTests(unittest.TestCase):
    def setUp(self):
        root = TemporaryDirectory()
        self.addCleanup(root.cleanup)
        self.directory = Path(root.name)
        self.inputs = self.directory / "github"
        copytree(EXAMPLE, self.inputs)
        self.manifest = self.inputs / "manifest.json"

    def packet(self):
        scenario, _ = load_github_review(self.manifest)
        return build_packet(scenario)

    def test_replay_preserves_the_roles_and_original_capture_fingerprint(self):
        packet = self.packet()
        baseline, reduced, denied, removed = packet["observations"]
        self.assertEqual([item["verdict"] for item in (baseline, reduced, denied, removed)],
                         ["detected", "still_granted", "inconclusive", "verified_removed"])
        self.assertEqual([item.get("effective_role") for item in (baseline, reduced, denied, removed)],
                         ["admin", "read", None, "none"])
        reference, = reduced["paths"][0]["evidence"]
        record = packet["evidence"][reference]
        capture = self.inputs / "role-reduced.json"
        self.assertEqual(record["sha256"], sha256(capture.read_bytes()).hexdigest())
        self.assertEqual(record["capture"]["role_lookup"]["request_id"], "SYNTHETIC:REDUCED:ROLE")
        self.assertIn("HTTP 403", denied["reason"])

    def test_failed_or_ambiguous_permission_responses_leave_access_unresolved(self):
        path = self.inputs / "access-removed.json"
        for status in (200.0, 301, 401, 403, 404, 429, 500, None):
            with self.subTest(status=status):
                capture = load_json(EXAMPLE / path.name)
                capture["role_lookup"]["status"] = status
                path.write_text(pretty_json(capture), encoding="utf-8")
                final = self.packet()["observations"][-1]
                self.assertEqual(final["verdict"], "inconclusive")
                self.assertEqual(final["source_coverage"], {SOURCE: "invalid"})
        capture = load_json(EXAMPLE / path.name)
        capture["role_lookup"]["data"]["role_name"] = "admin"
        path.write_text(pretty_json(capture), encoding="utf-8")
        self.assertIn("inconsistent role", self.packet()["observations"][-1]["reason"])

    def test_identity_and_observation_window_must_match_the_case(self):
        path = self.inputs / "access-removed.json"
        for location, key, modified, error in (
            (("account_lookup", "data"), "id", 71002, "account ID differs"),
            (("repository_lookup", "data"), "id", 55002, "repository ID differs"),
            ((), "origin", "github", "same origin"),
            ((), "started_at", "2026-11-20T07:34:59+00:00", "start strictly after"),
        ):
            with self.subTest(key=key, error=error):
                capture = load_json(EXAMPLE / path.name)
                target = capture
                for part in location:
                    target = target[part]
                target[key] = modified
                path.write_text(pretty_json(capture), encoding="utf-8")
                final = self.packet()["observations"][-1]
                self.assertEqual(final["verdict"], "inconclusive")
                self.assertIn(error, final["reason"])

    def test_replay_verifies_the_original_capture_bytes(self):
        output = self.directory / "packet.json"
        command = [sys.executable, "-B", str(ROOT / "replay.py"), "--github", str(self.manifest)]
        written = subprocess.run([*command, "--output", str(output)], capture_output=True, text=True)
        self.assertEqual(written.returncode, 0, written.stderr)
        verified = subprocess.run([*command, "--verify", str(output)], capture_output=True, text=True)
        self.assertEqual(verified.returncode, 0, verified.stderr)
        path = self.inputs / "access-removed.json"
        with path.open("ab") as capture:
            capture.write(b"\n")
        changed = subprocess.run([*command, "--verify", str(output)], capture_output=True, text=True)
        self.assertEqual(changed.returncode, 2)
        self.assertIn("GitHub captures", changed.stderr)

    def test_batch_and_ledger_accept_github_capture_evidence(self):
        manifest = self.directory / "batch.json"
        manifest.write_text(pretty_json({"cases": [{"github": "github/manifest.json",
                                                   "follow_up": "role-reduced"}]}), encoding="utf-8")
        output = self.directory / "batch"
        result = subprocess.run([sys.executable, "-B", str(ROOT / "batch_review.py"), str(manifest),
                                 "--output", str(output)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = (output / "report.md").read_text(encoding="utf-8")
        self.assertIn("| Still granted |", report)
        self.assertIn("effective role 'read'", report)
        entry, = load_json(output / "batch.json")["reviews"]
        self.assertEqual(entry, {"follow_up": "role-reduced", "packet": self.packet()})
        ledger = self.directory / "reviews.sqlite"
        replayed = subprocess.run([sys.executable, "-B", str(ROOT / "replay.py"),
                                   "--github", str(self.manifest), "--ledger", str(ledger)],
                                  capture_output=True, text=True)
        self.assertEqual(replayed.returncode, 0, replayed.stderr)
        self.assertTrue(ledger.is_file())
