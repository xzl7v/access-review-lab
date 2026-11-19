"""Normalize timestamped CSV access exports for the replay engine."""

from __future__ import annotations

import csv
from dataclasses import dataclass
from hashlib import sha256
from io import StringIO
from pathlib import Path
from typing import TextIO

from evidence import load_json, resolve_input_file
from review import source_columns


@dataclass(frozen=True)
class CsvInputs:
    scenario: dict
    paths: set[Path]
    source_provenance: dict | None


def _read_rows(stream: TextIO, path: Path, columns: tuple[str, ...]) -> list[dict[str, str]]:
    rows = []
    try:
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


def read_csv_exports(manifest_path: Path, *, include_provenance: bool = False) -> CsvInputs:
    """Read CSV sources and optionally record the raw bytes used for each source."""
    manifest = load_json(manifest_path)
    version = manifest.get("manifest_version", 1)
    if type(version) is not int or version not in (1, 2):
        raise ValueError("CSV manifest version must be 1 or 2")
    required_fields = {"file", "complete"}
    allowed_fields = required_fields | {"captured_at", "repository"} if version == 2 else required_fields
    case = manifest.get("case")
    snapshots = manifest.get("snapshots")
    if not isinstance(case, dict) or not isinstance(snapshots, list):
        raise ValueError("CSV manifest needs a case object and a snapshots list")
    directory = manifest_path.resolve().parent
    definitions = source_columns(case)
    exports = {}
    file_hashes = {}
    provenance = {} if include_provenance else None

    for index, snapshot in enumerate(snapshots):
        if not isinstance(snapshot, dict) or not isinstance(snapshot.get("sources"), dict):
            raise ValueError("each CSV snapshot needs a sources object")
        sources = {}
        for name, descriptor in snapshot["sources"].items():
            if name not in definitions:
                raise ValueError(f"unexpected snapshot source: {name}")
            if (not isinstance(descriptor, dict) or not required_fields <= descriptor.keys() <= allowed_fields
                    or type(descriptor["complete"]) is not bool):
                raise ValueError(f"{name} needs a file path and a boolean complete flag for this manifest version")
            path = resolve_input_file(directory, descriptor["file"], "CSV export")
            key = (path, definitions[name])
            if key not in exports:
                if include_provenance:
                    content = path.read_bytes()
                    fingerprint = sha256(content).hexdigest()
                    if file_hashes.setdefault(path, fingerprint) != fingerprint:
                        raise ValueError(f"CSV export changed during the review: {descriptor['file']}")
                    stream = StringIO(content.decode("utf-8-sig"), newline="")
                else:
                    stream = path.open(encoding="utf-8-sig", newline="")
                with stream:
                    exports[key] = _read_rows(stream, *key)
            rows = exports[key]
            sources[name] = {"complete": descriptor["complete"], "rows": rows}
            if version == 2:
                sources[name]["capture"] = {
                    "file": descriptor["file"],
                    "captured_at": descriptor.get("captured_at"),
                    "repository": descriptor.get("repository"),
                }
            if provenance is not None:
                provenance[f"/snapshots/{index}/sources/{name}"] = {
                    "file": descriptor["file"],
                    "sha256": file_hashes[path],
                    "record_count": len(rows),
                }
        snapshot["sources"] = sources

    return CsvInputs(manifest, {path for path, _ in exports}, provenance)


def load_csv_exports(manifest_path: Path) -> tuple[dict, set[Path]]:
    """Load a manifest into the replay schema and return its CSV paths."""
    loaded = read_csv_exports(manifest_path)
    return loaded.scenario, loaded.paths
