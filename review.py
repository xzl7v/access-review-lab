"""Evaluate repository role grants from dated workforce snapshots."""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime
from graphlib import CycleError, TopologicalSorter

REQUIRED_SOURCES = {
    "direct_grants": ("account_id", "repository", "role"),
    "team_memberships": ("account_id", "team_id"),
    "team_grants": ("team_id", "repository", "role"),
}
NESTED_SOURCE = "team_links"


def _text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise ValueError(f"{field} needs a nonempty string without surrounding whitespace")
    return value


def _timestamp(value: str, field: str) -> datetime:
    text = _text(value, field)
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.utcoffset() is None:
        raise ValueError(f"{field} must include a UTC offset")
    return parsed


def source_columns(case: dict) -> dict[str, tuple[str, ...]]:
    """Return the evidence sources and columns required by the case."""
    model = case.get("team_model", "flat")
    if model == "flat":
        return REQUIRED_SOURCES
    if model == "nested":
        return {**REQUIRED_SOURCES, NESTED_SOURCE: ("child_team_id", "parent_team_id")}
    raise ValueError(f"unsupported team model {model!r}")


def _source_issue(metadata: object, snapshot: dict, expected_time: datetime) -> dict | None:
    if not isinstance(metadata, dict):
        return {"reason": "Capture time and repository scope are required."}

    reasons = []
    timestamp = metadata.get("captured_at")
    try:
        captured_at = _timestamp(timestamp, "export capture time")
    except ValueError:
        reasons.append("Capture time must be an ISO timestamp with a UTC offset.")
    else:
        if captured_at != expected_time:
            reasons.append(f"Capture time {timestamp!r} differs from snapshot time {snapshot['captured_at']!r}.")

    repository = metadata.get("repository")
    if not isinstance(repository, str) or not repository or repository.strip() != repository:
        reasons.append("Repository scope is required.")
    elif repository != snapshot["repository"]:
        reasons.append(f"Export repository {repository!r} differs from snapshot repository {snapshot['repository']!r}.")

    if not reasons:
        return None
    issue = {"reason": " ".join(reasons)}
    if isinstance(metadata.get("file"), str):
        issue["file"] = metadata["file"]
    return issue


def _collect_sources(snapshot: dict, index: int, definitions: dict,
                     expected_time: datetime | None) -> tuple[dict, dict, dict]:
    raw = snapshot["sources"]
    if not isinstance(raw, dict):
        raise ValueError("snapshot sources must be an object")
    unexpected = set(raw) - definitions.keys()
    if unexpected:
        raise ValueError(f"unexpected snapshot sources: {', '.join(sorted(unexpected))}")

    evidence = {}
    coverage = {}
    issues = {}
    for name, columns in definitions.items():
        evidence[name] = []
        if name not in raw:
            coverage[name] = "missing"
            continue
        source = raw[name]
        if (not isinstance(source, dict) or type(source.get("complete")) is not bool
                or not isinstance(source.get("rows"), list)):
            raise ValueError(f"{name} needs a boolean complete flag and a list of rows")
        if expected_time is not None:
            issue = _source_issue(source.get("capture"), snapshot, expected_time)
            if issue is not None:
                coverage[name] = "invalid"
                issues[name] = issue
                continue
        coverage[name] = "complete" if source["complete"] else "partial"

        unique = set()
        for row_index, row in enumerate(source["rows"]):
            ref = f"/snapshots/{index}/sources/{name}/rows/{row_index}"
            if not isinstance(row, dict):
                raise ValueError(f"{ref} must be an object")
            key = tuple(_text(row.get(field), f"{ref}/{field}") for field in columns)
            if key in unique:
                raise ValueError(f"{name} repeats a grant or membership")
            unique.add(key)
            evidence[name].append((row, ref))
    return evidence, coverage, issues


def _team_graph(evidence: dict) -> dict:
    parents = defaultdict(list)
    for row, ref in evidence.get(NESTED_SOURCE, []):
        parents[row["child_team_id"]].append((row["parent_team_id"], ref))
    dependencies = {child: [parent for parent, _ in links] for child, links in parents.items()}
    try:
        list(TopologicalSorter(dependencies).static_order())
    except CycleError as exc:
        raise ValueError("team_links contains a cycle") from exc
    return parents


def _grant_paths(case: dict, evidence: dict) -> list[dict]:
    account = case["account_id"]
    target = (case["repository"], case["role"])
    paths = []
    for row, ref in evidence["direct_grants"]:
        if row["account_id"] == account and (row["repository"], row["role"]) == target:
            paths.append({"kind": "direct", "evidence": [ref]})

    team_grants = {
        row["team_id"]: ref
        for row, ref in evidence["team_grants"]
        if (row["repository"], row["role"]) == target
    }
    parents = _team_graph(evidence)
    for row, ref in evidence["team_memberships"]:
        if row["account_id"] != account:
            continue
        first_team = row["team_id"]
        frontier = deque([(first_team, [ref])])
        seen = {first_team}
        while frontier:
            team, chain = frontier.popleft()
            if team in team_grants:
                paths.append({"kind": "team", "team_id": team, "evidence": chain + [team_grants[team]]})
            for parent, parent_ref in parents.get(team, []):
                if parent not in seen:
                    seen.add(parent)
                    frontier.append((parent, chain + [parent_ref]))
    return paths


def assess(case: dict, snapshot: dict, index: int, *, check_source_capture: bool = False) -> dict:
    """Return an observation for a baseline or a single follow-up."""
    capture = _timestamp(snapshot["captured_at"], "captured_at")
    decision = _timestamp(case["decision"]["recorded_at"], "decision.recorded_at")
    snapshot_scope = _text(snapshot.get("repository"), "snapshot repository")
    stage = snapshot["stage"]
    if stage not in ("baseline", "follow_up"):
        raise ValueError(f"unsupported snapshot stage {stage!r}")

    result = {
        "snapshot": _text(snapshot.get("id"), "snapshot ID"),
        "captured_at": snapshot["captured_at"],
        "verdict": "inconclusive",
        "paths": [],
        "incomplete_sources": [],
        "source_coverage": {},
        "snapshot_ref": f"/snapshots/{index}",
    }
    if snapshot_scope != case["repository"]:
        return {**result, "reason": "The snapshot covers a different repository."}
    if stage == "follow_up" and capture <= decision:
        return {**result, "reason": "A follow-up needs a capture strictly after the decision."}
    if stage == "baseline" and not (_timestamp(case["employee_end_at"], "employee_end_at") <= capture < decision):
        return {**result, "reason": "The baseline must fall between departure and the decision."}

    evidence, coverage, issues = _collect_sources(
        snapshot, index, source_columns(case), capture if check_source_capture else None,
    )
    paths = _grant_paths(case, evidence)
    incomplete = [name for name, state in coverage.items() if state != "complete"]
    result.update(paths=paths, incomplete_sources=incomplete, source_coverage=coverage)
    issue_text = ""
    if issues:
        result["source_issues"] = issues
        details = []
        for name, issue in issues.items():
            label = f"{name} ({issue['file']})" if "file" in issue else name
            details.append(f"Invalid export {label}. {issue['reason']}")
        issue_text = " " + " ".join(details)
    if paths and stage == "baseline":
        return {**result, "verdict": "detected", "reason": "Grant paths are present after departure." + issue_text}
    if paths:
        return {**result, "verdict": "still_granted", "reason": "A grant path is visible in the follow-up." + issue_text}
    if incomplete:
        unavailable = [name for name in incomplete if name not in issues]
        reason = f"Sources required for verification: {', '.join(unavailable)}." if unavailable else ""
        return {**result, "reason": (reason + issue_text).strip()}
    if stage == "baseline":
        return {**result, "reason": "The baseline has no grant to verify against."}
    return {
        **result,
        "verdict": "verified_removed",
        "reason": "The complete follow-up shows zero grant paths in the modeled repository.",
    }


def replay(scenario: dict) -> dict:
    """Evaluate a case in input order and retain independent follow-up variants."""
    case = scenario["case"]
    for field in ("id", "account_id", "employee_id", "repository", "role"):
        _text(case.get(field), f"case.{field}")
    source_columns(case)
    decision = case["decision"]
    if decision["action"] != "revoke_role":
        raise ValueError("the replay expects a revoke_role decision")
    for field in ("reviewer", "reason"):
        _text(decision.get(field), f"decision.{field}")

    snapshots = scenario["snapshots"]
    if not isinstance(snapshots, list) or not snapshots or snapshots[0]["stage"] != "baseline":
        raise ValueError("the replay starts with a baseline snapshot")
    if any(snapshot["stage"] != "follow_up" for snapshot in snapshots[1:]):
        raise ValueError("snapshots after the baseline must be follow-ups")
    ids = [_text(snapshot.get("id"), "snapshot ID") for snapshot in snapshots]
    if len(ids) != len(set(ids)):
        raise ValueError("snapshot IDs must be unique")
    check_source_capture = scenario.get("manifest_version") == 2
    observations = [
        assess(case, snapshot, index, check_source_capture=check_source_capture)
        for index, snapshot in enumerate(snapshots)
    ]
    if observations[0]["verdict"] != "detected":
        message = "the baseline must show a grant path to the case's target role"
        if observations[0].get("source_issues"):
            message += ". " + observations[0]["reason"]
        raise ValueError(message)
    return {"case": case, "observations": observations}
