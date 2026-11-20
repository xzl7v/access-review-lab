"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { test } = require("node:test");
const { comparePaths, filterReviews, reviewCsv, caseBrief, evidenceFingerprints, verifyEvidenceFiles } =
  require("../web/review_logic.js");

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

test("source fingerprints come from CSV provenance and GitHub capture receipts", () => {
  const csv = evidenceFingerprints(sample("sample-packet"));
  const github = evidenceFingerprints(sample("sample-github"));
  const scenario = JSON.parse(fs.readFileSync(path.join(docs, "evidence.json"), "utf8"));
  assert.equal(csv.length, 5);
  assert.ok(csv.some(item => item.file === "memberships-after.csv"));
  assert.equal(github.length, 4);
  assert.ok(github.some(item => item.file === "lookup-denied.json"));
  assert.deepEqual(evidenceFingerprints(scenario), []);
});

test("original receipts and exports verify against the byte fingerprints", async () => {
  for (const [id, directory] of [["sample-packet", "csv"], ["sample-github", "github"]]) {
    const fingerprints = evidenceFingerprints(sample(id));
    const originalFiles = fingerprints.map(item => new File([
      fs.readFileSync(path.join(docs, "../examples", directory, item.file)),
    ], item.file));
    const results = await verifyEvidenceFiles(fingerprints, originalFiles);
    assert.equal(results.length, fingerprints.length);
    assert.ok(results.every(item => item.status === "match" && item.actual === item.sha256));
  }
});

test("the verifier distinguishes changed, missing, and unreadable source files", async () => {
  const fingerprints = evidenceFingerprints(sample("sample-packet"));
  const first = fingerprints[0].file;
  const second = fingerprints[1].file;
  const altered = new File([fs.readFileSync(path.join(docs, "../examples/csv", first)), "\n"], first);
  const unreadable = { name: second, arrayBuffer: async () => { throw Error("Read failed"); } };
  const results = await verifyEvidenceFiles(fingerprints, [altered, unreadable]);
  assert.equal(results[0].status, "mismatch");
  assert.notEqual(results[0].actual, results[0].sha256);
  assert.equal(results[1].status, "unreadable");
  assert.ok(results.slice(2).every(item => item.status === "missing"));
});

test("folder paths resolve repeated names and avoid hashing unrelated files", async () => {
  const [original] = evidenceFingerprints(sample("sample-packet"));
  const bytes = fs.readFileSync(path.join(docs, "../examples/csv", original.file));
  const fingerprints = ["before", "after"].map(folder => ({
    file: folder + "/" + original.file, sha256: original.sha256,
  }));
  const flat = new File([bytes], original.file);
  const unknown = { name: "unrelated.txt", arrayBuffer: async () => assert.fail("Unreferenced file was read") };
  const ambiguous = await verifyEvidenceFiles(fingerprints, [flat, unknown]);
  assert.deepEqual(ambiguous.map(item => item.status), ["ambiguous", "ambiguous"]);
  const chosenFolderFile = Object.assign(new File([bytes], original.file), {
    webkitRelativePath: "manifest-folder/after/" + original.file,
  });
  const resolved = await verifyEvidenceFiles(fingerprints, [chosenFolderFile, unknown]);
  assert.deepEqual(resolved.map(item => item.status), ["missing", "match"]);
});
