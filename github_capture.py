"""Save a read-only GitHub role capture for an offline access review."""

from __future__ import annotations

import argparse
from hashlib import sha256
import os
from pathlib import Path

from evidence import load_json, parse_json, pretty_json, resolve_input_file, write_atomic
from github_access import ACCESS_MODEL, CAPTURE_VERSION, SOURCE, capture_role, effective_role
from review import _timestamp


def load_github_review(manifest_path: Path) -> tuple[dict, set[Path]]:
    """Bind a local review decision to timestamped GitHub capture files."""
    manifest = load_json(manifest_path)
    case, entries = manifest.get("case"), manifest.get("snapshots")
    if not isinstance(case, dict) or not isinstance(entries, list) or len(entries) < 2:
        raise ValueError("GitHub reviews need a case, a baseline capture, and at least one follow-up")
    directory = manifest_path.resolve().parent
    paths = {manifest_path.resolve()}
    sources = []
    for entry in entries:
        if not isinstance(entry, dict) or entry.keys() != {"id", "file"}:
            raise ValueError("each GitHub snapshot needs an ID and a capture file")
        reference = entry["file"]
        path = resolve_input_file(directory, reference, "GitHub capture")
        if path in paths:
            raise ValueError(f"GitHub review repeats the capture file {reference}")
        paths.add(path)
        content = path.read_bytes()
        try:
            capture = parse_json(content.decode("utf-8-sig"), path.name)
            if type(capture.get("capture_version")) is not int or capture["capture_version"] != CAPTURE_VERSION:
                raise ValueError("GitHub capture version is unsupported")
            _timestamp(capture.get("captured_at"), "GitHub capture time")
        except ValueError as exc:
            raise ValueError(f"{reference}. {exc}") from exc
        sources.append({"file": reference, "sha256": sha256(content).hexdigest(), "capture": capture})

    baseline = sources[0]["capture"]
    try:
        role = effective_role(baseline)
    except ValueError as exc:
        raise ValueError(f"GitHub baseline {sources[0]['file']}. {exc}") from exc
    case = {
        **case,
        "access_model": ACCESS_MODEL,
        "account_id": role.login,
        "repository": role.repository,
        "role": "Any assigned role",
        "github_scope": {"repository_id": role.repository_id, "user_id": role.user_id,
                         "origin": baseline.get("origin")},
    }
    snapshots = [
        {
            "id": entry["id"],
            "stage": "baseline" if index == 0 else "follow_up",
            "captured_at": source["capture"]["captured_at"],
            "repository": role.repository,
            "sources": {SOURCE: source},
        }
        for index, (entry, source) in enumerate(zip(entries, sources))
    ]
    return {"case": case, "snapshots": snapshots}, paths


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True, metavar="OWNER/REPO")
    parser.add_argument("--account", required=True, metavar="LOGIN")
    parser.add_argument("--output", required=True, type=Path, metavar="FILE")
    args = parser.parse_args()
    try:
        capture = capture_role(args.repository, args.account, os.environ.get("GITHUB_TOKEN", ""))
        write_atomic(args.output, pretty_json(capture), replace=False)
    except (OSError, ValueError) as exc:
        parser.exit(2, f"Capture error · {exc}\n")
    print(f"Capture saved to {args.output}", flush=True)
    try:
        role = effective_role(capture)
    except ValueError as exc:
        parser.exit(2, f"Needs evidence · {exc}\n")
    print(f"Effective GitHub role · {role.role_name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
