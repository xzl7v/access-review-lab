"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { test } = require("node:test");
const { comparePaths, filterReviews, reviewCsv, caseBrief } = require("../web/review_logic.js");

const docs = path.resolve(__dirname, "../docs");
const page = fs.readFileSync(path.join(docs, "index.html"), "utf8");

function sample(id) {
  const pattern = new RegExp('id="' + id + '">([A-Za-z0-9+/=]+)</script>');
  const encoded = page.match(pattern)[1];
  return JSON.parse(Buffer.from(encoded, "base64").toString("utf8"));
}

const batch = sample("sample-batch").reviews.map(({ packet, follow_up }) => {
  const index = packet.observations.findIndex(item => item.snapshot === follow_up);
  return { packet, index, verdict: packet.observations[index].verdict };
});

test("queue filters combine outcome and case, account, source, or reason terms", () => {
  assert.deepEqual(filterReviews(batch, "still_granted", "  GITHUB  READ ").map(item => item.packet.case.id), ["GH-001"]);
  assert.deepEqual(filterReviews(batch, "inconclusive", "memberships-after.csv").map(item => item.packet.case.id), ["AR-001"]);
  assert.deepEqual(filterReviews(batch, "verified_removed", "github"), []);
});

test("the same grant path matches across independent snapshot pointers", () => {
  const packet = sample("sample-packet");
  const changes = comparePaths(packet, packet.observations[0], packet.observations[1]);
  assert.deepEqual(changes.map(item => item.state), ["absent", "retained"]);
  assert.equal(changes[0].absent, "direct_grants");
  assert.equal(changes[1].observed.team_id, "release-engineering");
});

test("missing, partial, or invalid membership sources keep the path unresolved", () => {
  const packet = sample("sample-packet");
  const baseline = packet.observations[0];
  for (const id of ["membership-export-missing", "stale-membership-export", "wrong-repository-export"]) {
    const selected = packet.observations.find(item => item.snapshot === id);
    const [direct, team] = comparePaths(packet, baseline, selected);
    assert.equal(direct.state, "absent", id);
    assert.equal(team.state, "unresolved", id);
  }
  const selected = packet.observations.find(item => item.snapshot === "both-paths-removed");
  selected.source_coverage.team_memberships = "partial";
  selected.source_coverage.team_grants = "partial";
  assert.equal(comparePaths(packet, baseline, selected)[1].state, "unresolved");
});

test("an empty complete export can establish absence and reverse comparisons remain directional", () => {
  const packet = sample("sample-packet");
  const [baseline, , removed] = packet.observations;
  assert.deepEqual(comparePaths(packet, baseline, removed).map(item => item.state), ["absent", "absent"]);
  assert.deepEqual(comparePaths(packet, removed, baseline).map(item => item.state), ["new", "new"]);
});

test("CSV contains selected results and protects textual spreadsheet cells", () => {
  const item = structuredClone(filterReviews(batch, "still_granted", "github")[0]);
  item.packet.case.account_id = ' =example "account"';
  const csv = reviewCsv([item]);
  assert.equal(csv.split("\r\n").length, 3);
  assert.match(csv, /"GH-001","' =example ""account"""/);
  assert.match(csv, /"GitHub".*"Still granted"/);
  assert.doesNotMatch(csv, /AR-103/);
});

test("a case brief includes the selected observation, request ID, and capture fingerprint", () => {
  const packet = sample("sample-github");
  const baseline = packet.observations[0];
  const denied = packet.observations.find(item => item.snapshot === "lookup-denied");
  const capture = packet.evidence[denied.snapshot_ref].sources.github_permission;
  const brief = caseBrief(packet, baseline, denied);
  assert.match(brief, /Needs evidence/);
  assert.match(brief, /HTTP 403/);
  assert.match(brief, /SYNTHETIC:DENIED:ROLE/);
  assert.ok(brief.includes(capture.sha256));
  assert.doesNotMatch(brief, /Verified removed/);
});
