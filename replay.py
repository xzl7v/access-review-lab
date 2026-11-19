"""Reproduce an access-removal case from local snapshots."""

from __future__ import annotations

import argparse
from pathlib import Path
import sqlite3

from csv_exports import read_csv_exports
from evidence import build_packet, canonical_json, load_json, pretty_json, write_atomic
from ledger import record_review
from review import assess, replay

__all__ = ["assess", "replay"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    input_options = parser.add_mutually_exclusive_group()
    input_options.add_argument("--scenario", type=Path, help="Read a scenario JSON file.")
    input_options.add_argument("--exports", type=Path, help="Read a manifest of local CSV exports.")
    parser.add_argument("--provenance", action="store_true", help="Include CSV file hashes and record numbers.")
    parser.add_argument("--json", action="store_true", help="Print the evidence packet as JSON.")
    parser.add_argument("--output", type=Path, help="Write the evidence packet to a JSON file.")
    parser.add_argument("--verify", type=Path, help="Verify an evidence packet against the scenario.")
    parser.add_argument("--ledger", type=Path, help="Record the case and evidence in a local SQLite database.")
    args = parser.parse_args()
    if args.provenance and args.exports is None:
        parser.error("--provenance requires --exports")

    try:
        input_path = args.scenario or args.exports or Path(__file__).with_name("scenario.json")
        paths = [path.resolve() for path in (input_path, args.output, args.verify, args.ledger) if path is not None]
        if len(paths) != len(set(paths)):
            raise ValueError("input, output, verification packet, and ledger need distinct paths")
        source_provenance = None
        if args.exports is not None:
            loaded = read_csv_exports(input_path, include_provenance=args.provenance)
            if loaded.paths.intersection(paths):
                raise ValueError("CSV exports, output, verification packet, and ledger need distinct paths")
            scenario, source_provenance = loaded.scenario, loaded.source_provenance
        else:
            scenario = load_json(input_path)
        packet = build_packet(scenario, source_provenance=source_provenance)
        content = pretty_json(packet)
        if args.verify:
            submitted = load_json(args.verify)
            if canonical_json(submitted) != canonical_json(packet):
                scope = "replayed scenario or CSV provenance" if args.provenance else "replayed scenario"
                raise ValueError(f"evidence packet does not match the {scope}")
        if args.ledger:
            record_review(args.ledger, packet)
        if args.output:
            write_atomic(args.output, content)
    except (OSError, ValueError, TypeError, KeyError, AttributeError, sqlite3.Error) as exc:
        parser.exit(2, f"Review error · {exc}\n")

    if args.json:
        print(content, end="")
        return 0
    if args.verify:
        print(f"Verified {args.verify}")
    for item in packet["observations"]:
        print(f"{item['snapshot']:27} {item['verdict']:18} {item['reason']}")
        for path in item["paths"]:
            name = path.get("team_id", path["kind"])
            print(f"  {name} · {' → '.join(path['evidence'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
