"""Build a deterministic, inspectable record of a review."""

from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
from tempfile import NamedTemporaryFile

from review import replay

PACKET_VERSION = 1


def load_json(path: Path) -> dict:
    def unique_keys(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate JSON key {key!r} in {path.name}")
            value[key] = item
        return value

    value = json.loads(path.read_text(encoding="utf-8-sig"), object_pairs_hook=unique_keys)
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must contain a JSON object")
    return value


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def digest(value: object) -> str:
    return sha256(canonical_json(value).encode("utf-8")).hexdigest()


def pretty_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n"


def resolve_pointer(document: dict, pointer: str) -> object:
    value = document
    for field in pointer.split("/")[1:]:
        key = field.replace("~1", "/").replace("~0", "~")
        value = value[int(key)] if isinstance(value, list) else value[key]
    return value


def build_packet(scenario: dict) -> dict:
    scenario = deepcopy(scenario)
    result = replay(scenario)
    references = {"/case/decision"}
    for observation in result["observations"]:
        references.add(observation["snapshot_ref"])
        for path in observation["paths"]:
            references.update(path["evidence"])
    return {
        "packet_version": PACKET_VERSION,
        "input_sha256": digest(scenario),
        **result,
        "evidence": {ref: resolve_pointer(scenario, ref) for ref in sorted(references)},
    }


def write_atomic(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with NamedTemporaryFile("w", encoding="utf-8", newline="\n", dir=path.parent, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(content)
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
