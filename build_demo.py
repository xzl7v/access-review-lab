"""Generate the portable demo, evidence viewer, and bundled packet."""

from __future__ import annotations

import argparse
from base64 import b64encode
from datetime import datetime
from hashlib import sha256
from html import escape
from pathlib import Path
from string import Template

from batch_review import build_batch_packet, load_batch
from csv_exports import read_csv_exports
from evidence import build_packet, load_json, pretty_json, write_atomic

ROOT = Path(__file__).resolve().parent
STATES = {
    "detected": ("snapshot-baseline", "Before decision", "warning", "Access detected"),
    "still_granted": ("snapshot-direct", "Direct grant removed", "warning", "Still granted"),
    "verified_removed": ("snapshot-verified", "Removal verified", "verified", "Verified removed"),
    "inconclusive": ("snapshot-inconclusive", "Membership export missing", "pending", "Verification pending"),
}


def clock(value: str, *, dated: bool = False) -> str:
    timestamp = datetime.fromisoformat(value)
    return timestamp.strftime("%d %b %Y · %H:%M" if dated else "%H:%M")


def local_clock(value: str, *, dated: bool = False) -> str:
    offset = datetime.fromisoformat(value).strftime("%z")
    return f"{clock(value, dated=dated)} UTC{offset[:3]}:{offset[3:]}"


def record(values: dict, reference: str, *, label: str = "Snapshot record") -> str:
    fields = "\n".join(
        f"<div><dt>{escape(name)}</dt><dd><code>{escape(str(value))}</code></dd></div>"
        for name, value in values.items()
    )
    return (
        f'<dl class="record">{fields}</dl>'
        f'<div class="reference">{label}<code>{escape(reference)}</code></div>'
    )


def evidence_tab(identifier: str, title: str, description: str, content: str) -> str:
    return (
        f'<article id="{identifier}"><h3>{title}</h3>'
        f"<p>{description}</p>{content}</article>"
    )


def access_path(observation: dict, kind: str) -> dict | None:
    return next((path for path in observation["paths"] if path["kind"] == kind), None)


def membership_view(packet: dict, observation: dict, previous: dict, identifier: str) -> tuple[str, str]:
    """Return the edge control and evidence for a specific observed membership."""
    verdict = observation["verdict"]
    evidence = packet["evidence"]
    if verdict in ("detected", "still_granted"):
        path = access_path(observation, "team")
        reference = path["evidence"][0]
        return "Member of", evidence_tab(
            identifier, "Team membership", "This snapshot lists the account as a member of the team.",
            record(evidence[reference], reference),
        )

    scope = f'{observation["snapshot_ref"]}/sources'
    if verdict == "verified_removed":
        old_path = access_path(previous, "team")
        reference = old_path["evidence"][0]
        row = evidence[reference]
        snapshot = evidence[observation["snapshot_ref"]]
        member_rows = snapshot["sources"]["team_memberships"]["rows"]
        matches = sum(item["account_id"] == packet["case"]["account_id"] for item in member_rows)
        if matches:
            raise ValueError("the verified demo scene expects no remaining memberships for the account")
        return "No membership", evidence_tab(
            identifier, "Membership removed",
            "The earlier snapshot lists the account. The complete follow-up has no matching membership.",
            f'<strong class="comparison-heading">{clock(previous["captured_at"])} · Earlier snapshot</strong>'
            + record(row, reference)
            + f'<strong class="comparison-heading">{clock(observation["captured_at"])} · Follow-up snapshot</strong>'
            + record({"Complete": "true", "Matching memberships": matches}, f"{scope}/team_memberships",
                     label="Snapshot source"),
        )

    labels = {"team_memberships": "Membership export", "direct_grants": "Direct grants", "team_grants": "Team grants"}
    coverage = {labels[key]: state.title() for key, state in observation["source_coverage"].items()}
    return "Membership unknown", evidence_tab(
        identifier, "Membership export missing",
        "Collect a complete <code>team_memberships</code> export for this follow-up to verify the team path.",
        record(coverage, scope, label="Snapshot sources"),
    )


def render_scene(packet: dict, observation: dict, previous: dict, baseline: dict) -> str:
    case = packet["case"]
    source = packet["evidence"][observation["snapshot_ref"]]["sources"]
    evidence = packet["evidence"]
    verdict = observation["verdict"]
    scene, _, badge_class, badge = STATES[verdict]
    account, repository, role = map(escape, (case["account_id"], case["repository"], case["role"]))
    team = access_path(previous, "team")["team_id"]
    capture = observation["captured_at"]
    decision = case["decision"]["recorded_at"]
    scope = f'{observation["snapshot_ref"]}/sources'
    headings = {
        "detected": ("Which grants remained after departure?",
                     f"Workforce record <strong>{escape(case['employee_id'])}</strong> ended on "
                     f"{datetime.fromisoformat(case['employee_end_at']).strftime('%d %b %Y')}. "
                     f"The baseline shows direct and team {role} grants for <strong>{account}</strong>.",
                     "Baseline snapshot", "Access paths before the decision", ""),
        "still_granted": (f"Why does {role} remain?",
                          f"The direct grant was removed. Membership in <strong>{escape(team)}</strong> "
                          f"still grants {role} on this repository.",
                          "Follow-up snapshot", "Remaining access path", ""),
        "verified_removed": (f"What proves {role} was removed?",
                             f"The complete follow-up shows zero direct {role} grants and zero team memberships "
                             f"for <strong>{account}</strong>.",
                             "Follow-up snapshot", "Access path after removal", "cut"),
        "inconclusive": ("What's missing from the evidence?",
                         f"The direct {role} grant check is complete. The missing membership export "
                         f"leaves the team path for <strong>{account}</strong> unresolved.",
                         "Alternative follow-up", "Access path under review", "unknown"),
    }
    heading, subtitle, capture_title, diagram_title, edge_class = headings[verdict]

    membership_label, member_html = membership_view(packet, observation, previous, f"{scene}-membership")
    [(team_index, team_row)] = [
        (i, row) for i, row in enumerate(source["team_grants"]["rows"])
        if (row["team_id"], row["repository"], row["role"]) == (team, case["repository"], case["role"])
    ]
    team_description = {
        "verified_removed": f"The team retains {role} on the repository. The account's membership was removed.",
        "inconclusive": f"The snapshot grants {role} to the team. The account's membership is unresolved.",
    }.get(verdict, f"The snapshot grants {role} on the repository to the team.")
    team_heading = "Team grant still present" if verdict == "verified_removed" else "Team grant"
    team_html = evidence_tab(f"{scene}-grant", team_heading, team_description,
                             record(team_row, f"{scope}/team_grants/rows/{team_index}"))

    direct = access_path(observation, "direct")
    if direct:
        [direct_ref] = direct["evidence"]
        direct_label = "View direct grant"
        direct_status = '<span class="present">Present</span>'
        direct_html = evidence_tab(f"{scene}-direct", "Direct grant", "The baseline lists this direct grant.",
                                   record(evidence[direct_ref], direct_ref))
    else:
        checks = source["direct_grants"]
        matches = sum(
            (row["account_id"], row["repository"], row["role"]) ==
            (case["account_id"], case["repository"], case["role"])
            for row in checks["rows"]
        )
        direct_ref = f"{scope}/direct_grants"
        summary = record({"Complete": str(checks["complete"]).lower(), "Matching grants": matches},
                         direct_ref, label="Snapshot source")
        direct_label = "View direct check"
        direct_status = '<span class="removal">Removed</span>'
        if verdict == "still_granted":
            [old_ref] = access_path(baseline, "direct")["evidence"]
            summary = ('<strong class="comparison-heading">Before the decision</strong>'
                       + record(evidence[old_ref], old_ref)
                       + '<strong class="comparison-heading">Follow-up snapshot</strong>' + summary)
            direct_label = "View change"
        direct_html = evidence_tab(f"{scene}-direct", "Direct grant check",
                                   f"The complete follow-up has zero matching direct {role} grants.", summary)

    return f'''    <div id="{scene}" class="snapshot-panel">
      <section class="overview" aria-labelledby="{scene}-finding">
        <div class="overview-text">
          <div class="tags"><span class="case-id">CASE {escape(case["id"])}</span><span class="badge {badge_class}">{badge}</span></div>
          <h1 id="{scene}-finding">{heading}</h1>
          <p>{subtitle}</p>
        </div>
        <dl class="capture">
          <dt>{capture_title}</dt>
          <dd><time datetime="{escape(capture)}">{local_clock(capture, dated=True)}</time></dd>
        </dl>
      </section>
      <div class="workspace">
        <section class="panel" aria-labelledby="{scene}-diagram">
          <h2 id="{scene}-diagram" class="panel-title">{diagram_title}</h2>
          <div class="path-canvas">
            <div class="path-track">
              <div class="path-node"><span class="path-caption">Account</span><strong class="path-name">{account}</strong></div>
              <button class="edge {edge_class}" type="button" data-select aria-controls="{scene}-membership" aria-pressed="true"><span>{membership_label}</span></button>
              <div class="path-node team"><span class="path-caption">Team</span><strong class="path-name">{escape(team)}</strong></div>
              <button class="edge" type="button" data-select aria-controls="{scene}-grant" aria-pressed="false"><span>Grants {role}</span></button>
              <div class="path-node"><span class="path-caption">Repository</span><strong class="path-name">{repository}</strong></div>
            </div>
          </div>
          <div class="direct-change">
            <div><strong>Direct grant</strong> {direct_status}</div>
            <button class="direct-button" type="button" data-select aria-controls="{scene}-direct" aria-pressed="false">{direct_label}</button>
          </div>
        </section>
        <section class="panel" aria-labelledby="{scene}-evidence">
          <h2 id="{scene}-evidence" class="panel-title">Source evidence</h2>
          <div class="evidence-stack" aria-live="polite">
            {member_html}
            {team_html}
            {direct_html}
          </div>
        </section>
      </div>
      <p class="decision"><strong>Reviewer decision</strong><time datetime="{escape(decision)}">{local_clock(decision)}</time><span>Revoke {role} on {repository}</span></p>
    </div>'''


def render_demo(packet: dict, layout: Template) -> str:
    observations = packet["observations"]
    if [item["verdict"] for item in observations] != list(STATES):
        raise ValueError("the portfolio demo expects the four bundled observations in order")
    baseline, previous, verified, pending = observations
    all_complete = {name: "complete" for name in ("direct_grants", "team_memberships", "team_grants")}
    if any(item["source_coverage"] != all_complete for item in (baseline, previous, verified)):
        raise ValueError("the first three demo scenes require complete flat-team sources")
    if pending["source_coverage"] != {**all_complete, "team_memberships": "missing"}:
        raise ValueError("the alternative demo scene requires the membership export to be missing")
    if ([path["kind"] for path in baseline["paths"]] != ["direct", "team"]
            or [path["kind"] for path in previous["paths"]] != ["team"]):
        raise ValueError("the demo expects direct and team grants followed by only the team grant")
    if pending["captured_at"] != verified["captured_at"]:
        raise ValueError("the final two demo scenes must be variants of the same follow-up time")
    tabs = []
    for observation in observations:
        key, title, _, _ = STATES[observation["verdict"]]
        selected = str(observation is previous).lower()
        time = observation["captured_at"]
        tabs.append(
            f'      <button type="button" data-snapshot-target aria-controls="{key}" aria-pressed="{selected}">'
            f'<time datetime="{escape(time)}">{clock(time)}</time><span>{title}</span></button>'
        )
    navigation = '    <nav class="snapshot-switcher" aria-label="Snapshots" hidden>\n' + "\n".join(tabs) + "\n    </nav>"
    encoded_packet = b64encode(pretty_json(packet).encode("utf-8")).decode("ascii")
    return layout.substitute(
        case_id=escape(packet["case"]["id"]),
        navigation=navigation,
        scenes="\n".join(render_scene(packet, observation, previous, baseline) for observation in observations),
        evidence_payload=encoded_packet,
    )


def render_viewer() -> str:
    sample = read_csv_exports(ROOT / "examples" / "csv" / "manifest.json", include_provenance=True)
    packet = build_packet(sample.scenario, source_provenance=sample.source_provenance)
    batch = build_batch_packet(load_batch(ROOT / "examples" / "batch" / "manifest.json"))
    script = (ROOT / "web" / "viewer.js").read_text(encoding="utf-8")
    layout = Template((ROOT / "web" / "viewer.html").read_text(encoding="utf-8"))
    return layout.substitute(
        evidence_payload=b64encode(pretty_json(packet).encode("utf-8")).decode("ascii"),
        batch_payload=b64encode(pretty_json(batch).encode("utf-8")).decode("ascii"),
        script_hash=b64encode(sha256(script.encode("utf-8")).digest()).decode("ascii"),
        viewer_script=script,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Check that the published assets match the case.")
    args = parser.parse_args()
    case_data = load_json(ROOT / "scenario.json")
    packet = build_packet(case_data)
    layout = Template((ROOT / "web" / "template.html").read_text(encoding="utf-8"))
    assets = {
        ROOT / "docs" / "index.html": render_demo(packet, layout),
        ROOT / "docs" / "evidence.json": pretty_json(packet),
        ROOT / "docs" / "viewer.html": render_viewer(),
    }
    for path, content in assets.items():
        if args.check:
            if not path.is_file() or path.read_text(encoding="utf-8") != content:
                parser.exit(1, f"Demo asset out of date · {path.relative_to(ROOT)}\n")
        else:
            write_atomic(path, content)
    print("Demo and viewer match the replay." if args.check else "Generated the demo and viewer in docs/.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
