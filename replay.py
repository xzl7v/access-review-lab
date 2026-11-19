"""Reproduce an access-removal case from local snapshots."""

from __future__ import annotations

import argparse
from pathlib import Path
import sqlite3

from evidence import build_packet, canonical_json, load_json, pretty_json, write_atomic
from ledger import record_review
from review import assess, replay

__all__ = ["assess", "replay"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", type=Path, default=Path(__file__).with_name("scenario.json"))
    parser.add_argument("--json", action="store_true", help="Print the evidence packet as JSON.")
    parser.add_argument("--output", type=Path, help="Write the evidence packet to a JSON file.")
    parser.add_argument("--verify", type=Path, help="Verify an evidence packet against the scenario.")
    parser.add_argument("--ledger", type=Path, help="Record the case and evidence in a local SQLite database.")
    args = parser.parse_args()

    try:
        paths = [path.resolve() for path in (args.scenario, args.output, args.verify, args.ledger) if path is not None]
        if len(paths) != len(set(paths)):
            raise ValueError("scenario, output, verification packet, and ledger need distinct paths")
        scenario = load_json(args.scenario)
        packet = build_packet(scenario)
        content = pretty_json(packet)
        if args.verify:
            submitted = load_json(args.verify)
            if canonical_json(submitted) != canonical_json(packet):
                raise ValueError("evidence packet does not match the replayed scenario")
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
