"""Replay several access reviews and write a triage report with evidence."""

from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path
from tempfile import TemporaryDirectory

from csv_exports import read_csv_exports
from evidence import build_packet, load_json, pretty_json, resolve_input_file

VERDICTS = {
    "still_granted": (0, "Still granted"),
    "inconclusive": (1, "Needs evidence"),
    "verified_removed": (2, "Verified removed"),
}
MARKDOWN_ENTITIES = str.maketrans({char: f"&#{ord(char)};" for char in r"\|&<>[]*_~`"})


def _read_case(directory: Path, entry: object, *, include_provenance: bool) -> tuple[dict, dict]:
    input_names = {"scenario", "exports"}
    if not isinstance(entry, dict):
        raise ValueError("each case entry must be an object")
    inputs = entry.keys() & input_names
    if len(inputs) != 1 or entry.keys() - (input_names | {"follow_up"}):
        raise ValueError("each case needs one scenario or exports path and an optional follow_up")

    kind = inputs.pop()
    input_path = resolve_input_file(directory, entry[kind], "case input")
    if kind == "exports":
        loaded = read_csv_exports(input_path, include_provenance=include_provenance)
        packet = build_packet(loaded.scenario, source_provenance=loaded.source_provenance)
    else:
        packet = build_packet(load_json(input_path))
    case_id = packet["case"]["id"]
    follow_ups = packet["observations"][1:]
    if not follow_ups:
        raise ValueError(f"case {case_id} has no follow-up snapshots")
    if "follow_up" not in entry:
        if len(follow_ups) != 1:
            raise ValueError(f"case {case_id} has multiple follow-ups. Specify a follow_up snapshot ID.")
        return packet, follow_ups[0]

    for observation in follow_ups:
        if observation["snapshot"] == entry["follow_up"]:
            return packet, observation
    raise ValueError(f"{entry['follow_up']!r} is not a follow-up snapshot in case {case_id}")


def load_batch(manifest_path: Path, *, include_provenance: bool = False) -> list[tuple[dict, dict]]:
    """Build and prioritize a packet and selected follow-up for each case."""
    manifest = load_json(manifest_path)
    entries = manifest.get("cases")
    if not isinstance(entries, list) or not entries:
        raise ValueError("batch manifest needs a nonempty cases list")
    directory = manifest_path.resolve().parent

    reviews = []
    case_ids = set()
    for index, entry in enumerate(entries, start=1):
        try:
            packet, observation = _read_case(directory, entry, include_provenance=include_provenance)
        except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
            raise ValueError(f"case entry {index}: {exc}") from exc
        case_id = packet["case"]["id"]
        if case_id in case_ids:
            raise ValueError(f"duplicate case ID: {case_id}")
        case_ids.add(case_id)
        reviews.append((packet, observation))
    reviews.sort(key=lambda item: (VERDICTS[item[1]["verdict"]][0], item[0]["case"]["id"]))
    return reviews


def _render_report(reviews: list[tuple[dict, dict]]) -> str:
    counts = Counter(observation["verdict"] for _, observation in reviews)
    totals = ", ".join(f"{counts[verdict]} {label.lower()}" for verdict, (_, label) in VERDICTS.items())
    case_label = "case" if len(reviews) == 1 else "cases"
    lines = [
        "# Access review report",
        "",
        f"{len(reviews)} {case_label}. {totals}.",
        "",
        "| Case | Account | Repository | Role | Follow-up | Result | Reason | Evidence |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for index, (packet, observation) in enumerate(reviews, start=1):
        case = packet["case"]
        verdict = observation["verdict"]
        reason = observation["reason"]
        if verdict == "still_granted":
            paths = (
                "Direct grant" if path["kind"] == "direct" else f"Team grant via {path['team_id']}"
                for path in observation["paths"]
            )
            reason = ", ".join(dict.fromkeys(paths))
        follow_up = f"{observation['snapshot']} ({observation['captured_at']})"
        fields = (case["id"], case["account_id"], case["repository"], case["role"],
                  follow_up, VERDICTS[verdict][1], reason)
        cells = [" ".join(field.splitlines()).translate(MARKDOWN_ENTITIES) for field in fields]
        cells.append(f"[Packet](evidence/{index:03d}.json)")
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines) + "\n"


def write_batch(manifest_path: Path, output: Path, *, include_provenance: bool = False) -> Path:
    """Publish one complete report directory from a validated batch."""
    output = output.absolute()
    if output.exists() or output.is_symlink():
        raise FileExistsError(f"output path already exists: {output}. Choose a new directory.")
    reviews = load_batch(manifest_path, include_provenance=include_provenance)
    output.parent.mkdir(parents=True, exist_ok=True)

    with TemporaryDirectory(prefix=".access-review-", dir=output.parent) as staging:
        bundle = Path(staging) / "batch"
        evidence = bundle / "evidence"
        evidence.mkdir(parents=True)
        for index, (packet, _) in enumerate(reviews, start=1):
            (evidence / f"{index:03d}.json").write_text(pretty_json(packet), encoding="utf-8", newline="\n")
        (bundle / "report.md").write_text(_render_report(reviews), encoding="utf-8", newline="\n")
        bundle.rename(output)
    return output / "report.md"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path, help="JSON manifest containing the cases to review.")
    parser.add_argument("--output", type=Path, required=True, help="New directory for the report and evidence.")
    parser.add_argument("--provenance", action="store_true", help="Include source provenance in CSV packets.")
    args = parser.parse_args()

    try:
        report = write_batch(args.manifest, args.output, include_provenance=args.provenance)
    except (OSError, ValueError) as exc:
        parser.exit(2, f"Batch review error · {exc}\n")
    print(f"Report written to {report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
