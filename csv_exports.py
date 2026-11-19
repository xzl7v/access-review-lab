"""Normalize timestamped CSV access exports for the replay engine."""

from __future__ import annotations

import csv
from pathlib import Path

from evidence import load_json, resolve_input_file
from review import source_columns


def _read_rows(path: Path, columns: tuple[str, ...]) -> list[dict[str, str]]:
    rows = []
    try:
        with path.open(encoding="utf-8-sig", newline="") as stream:
            reader = csv.DictReader(stream, strict=True)
            header = reader.fieldnames
            if not header or "" in header or len(header) != len(set(header)):
                raise ValueError(f"{path.name} needs a CSV header with unique column names")
            missing = [column for column in columns if column not in header]
            if missing:
                raise ValueError(f"{path.name} is missing CSV columns: {', '.join(missing)}")

            for row in reader:
                if None in row or None in row.values():
                    raise ValueError(f"{path.name}:{reader.line_num} has a different field count from the header")
                rows.append({column: row[column] for column in columns})
    except csv.Error as exc:
        raise ValueError(f"{path.name} contains invalid CSV: {exc}") from exc
    return rows


def load_csv_exports(manifest_path: Path) -> tuple[dict, set[Path]]:
    """Load a manifest into the replay schema and return its CSV paths."""
    manifest = load_json(manifest_path)
    case = manifest.get("case")
    snapshots = manifest.get("snapshots")
    if not isinstance(case, dict) or not isinstance(snapshots, list):
        raise ValueError("CSV manifest needs a case object and a snapshots list")
    directory = manifest_path.resolve().parent
    definitions = source_columns(case)
    exports = {}

    for snapshot in snapshots:
        if not isinstance(snapshot, dict) or not isinstance(snapshot.get("sources"), dict):
            raise ValueError("each CSV snapshot needs a sources object")
        sources = {}
        for name, descriptor in snapshot["sources"].items():
            if name not in definitions:
                raise ValueError(f"unexpected snapshot source: {name}")
            if (not isinstance(descriptor, dict) or descriptor.keys() != {"file", "complete"}
                    or type(descriptor["complete"]) is not bool):
                raise ValueError(f"{name} needs a file path and a boolean complete flag")
            path = resolve_input_file(directory, descriptor["file"], "CSV export")
            key = (path, definitions[name])
            if key not in exports:
                exports[key] = _read_rows(*key)
            sources[name] = {"complete": descriptor["complete"], "rows": exports[key]}
        snapshot["sources"] = sources

    return manifest, {path for path, _ in exports}
