"use strict";

const verdicts = {
  detected: "Access detected",
  still_granted: "Still granted",
  verified_removed: "Verified removed",
  inconclusive: "Needs evidence",
};
const coverageLabels = { complete: "Complete", partial: "Partial", missing: "Missing", invalid: "Invalid" };
const githubModel = "github_effective";
const githubSource = "github_permission";
const isHash = value => typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
const sources = {
  direct_grants: { label: "Direct grants", record: "Direct grant", fields: ["account_id", "repository", "role"] },
  team_memberships: { label: "Team memberships", record: "Team membership", fields: ["account_id", "team_id"] },
  team_grants: { label: "Team grants", record: "Team grant", fields: ["team_id", "repository", "role"] },
  team_links: { label: "Team links", record: "Team link", fields: ["child_team_id", "parent_team_id"] },
  github_permission: { label: "GitHub role capture", record: "GitHub role response" },
};

function inputType(packet) {
  if (packet.case.access_model === githubModel) return "GitHub";
  return packet.packet_version === 2 ? "CSV with provenance" : "Scenario";
}

function sourcePath(value) {
  if (typeof value !== "string" || !value.trim()) return null;
  const normal = value.replaceAll("\\", "/");
  const parts = normal.split("/").filter(part => part && part !== ".");
  return normal.startsWith("/") || /^[a-z]:/i.test(normal) || parts.includes("..")
    ? null : parts.join("/") || null;
}

function evidenceFingerprints(packet) {
  const records = packet.case.access_model === githubModel
    ? packet.observations.map(observation => packet.evidence[observation.snapshot_ref]?.sources?.[githubSource])
    : Object.values(packet.provenance?.sources ?? {});
  const fingerprints = new Map();
  for (const record of records) {
    const file = sourcePath(record?.file);
    if (!file || !isHash(record.sha256)) continue;
    fingerprints.set(JSON.stringify([file, record.sha256]), { file, sha256: record.sha256 });
  }
  return Array.from(fingerprints.values()).sort((left, right) => left.file.localeCompare(right.file));
}

async function verifyEvidenceFiles(fingerprints, files) {
  const crypto = globalThis.crypto?.subtle;
  if (!crypto) throw new Error("SHA-256 verification requires a browser with Web Crypto.");
  const fileName = path => path.split("/").at(-1);
  const expectedPaths = new Map();
  for (const { file } of fingerprints) {
    const name = fileName(file);
    const paths = expectedPaths.get(name) ?? new Set();
    paths.add(file);
    expectedPaths.set(name, paths);
  }
  const byPath = new Map();
  const byName = new Map();
  for (const file of files) {
    const relative = file.webkitRelativePath;
    const path = sourcePath(relative ? relative.split("/").slice(1).join("/") : file.name);
    if (!path) continue;
    const index = relative ? byPath : byName;
    const entries = index.get(path) ?? [];
    entries.push(file);
    index.set(path, entries);
  }
  const hashes = new Map();
  const results = [];
  for (const fingerprint of fingerprints) {
    const name = fileName(fingerprint.file);
    const exact = byPath.get(fingerprint.file);
    const candidates = exact ?? byName.get(name) ?? [];
    if (!candidates.length) {
      results.push({ ...fingerprint, status: "missing" });
    } else if (candidates.length > 1 || (!exact && expectedPaths.get(name).size > 1)) {
      results.push({ ...fingerprint, status: "ambiguous" });
    } else {
      const file = candidates[0];
      if (!hashes.has(file)) {
        try {
          const digest = await crypto.digest("SHA-256", await file.arrayBuffer());
          hashes.set(file, Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join(""));
        } catch {
          hashes.set(file, null);
        }
      }
      const actual = hashes.get(file);
      const status = actual === null ? "unreadable" : actual === fingerprint.sha256 ? "match" : "mismatch";
      results.push({ ...fingerprint, status, actual });
    }
  }
  return results;
}

function filterReviews(reviews, outcome, query) {
  const terms = query.toLowerCase().trim().split(/\s+/).filter(Boolean);
  return reviews.filter(item => {
    if (outcome !== "all" && item.verdict !== outcome) return false;
    const { packet, index } = item;
    const { id, account_id, repository, role } = packet.case;
    const observation = packet.observations[index];
    const text = [id, account_id, repository, role, inputType(packet), verdicts[item.verdict],
      observation.snapshot, observation.reason].join(" ").toLowerCase();
    return terms.every(term => text.includes(term));
  });
}

function sourceName(reference) {
  return reference.split("/")[4];
}

function rowIdentity(name, row) {
  const fields = Object.hasOwn(sources, name) ? sources[name].fields : null;
  if (!fields || !row || !fields.every(field => typeof row[field] === "string")) return null;
  return JSON.stringify(fields.map(field => row[field]));
}

function pathIdentity(packet, path) {
  return JSON.stringify([path.kind, path.team_id, ...path.evidence.map(reference => {
    const name = sourceName(reference);
    return [name, rowIdentity(name, packet.evidence[reference]) ?? reference];
  })]);
}

function absentSource(packet, path, selected) {
  const snapshot = packet.evidence[selected.snapshot_ref];
  for (const reference of path.evidence) {
    const name = sourceName(reference);
    const source = snapshot?.sources?.[name];
    const key = rowIdentity(name, packet.evidence[reference]);
    if (key === null || selected.source_coverage[name] !== "complete" || source?.complete !== true
        || !Array.isArray(source.rows)) continue;
    const rows = source.rows.map(row => rowIdentity(name, row));
    if (rows.every(row => row !== null) && !rows.includes(key)) return name;
  }
  return null;
}

function comparePaths(packet, reference, selected) {
  const before = new Map(reference.paths.map(path => [pathIdentity(packet, path), path]));
  const after = new Map(selected.paths.map(path => [pathIdentity(packet, path), path]));
  const changes = [];
  for (const [key, path] of before) {
    const observed = after.get(key);
    const absent = observed ? null : absentSource(packet, path, selected);
    const state = observed ? "retained" : absent ? "absent" : "unresolved";
    changes.push({ path, observed, absent, state });
  }
  for (const [key, path] of after) {
    if (!before.has(key)) changes.push({ path, observed: path, absent: null, state: "new" });
  }
  return changes;
}

function csvField(value) {
  const raw = String(value ?? "");
  const protectedValue = /^[\t\r\n]|^[\s\u200b-\u200f\ufeff]*[=+@\-＝＋＠－]/u.test(raw) ? "'" + raw : raw;
  return '"' + protectedValue.replaceAll('"', '""') + '"';
}

function reviewCsv(reviews) {
  const rows = [["Case", "Account", "Repository", "Role", "Source", "Follow-up", "Captured at", "Outcome", "Reason", "Input SHA-256"]];
  for (const { packet, index, verdict } of reviews) {
    const review = packet.case;
    const observation = packet.observations[index];
    rows.push([review.id, review.account_id, review.repository, review.role, inputType(packet), observation.snapshot,
      observation.captured_at, verdicts[verdict], observation.reason, packet.input_sha256]);
  }
  return rows.map(row => row.map(csvField).join(",")).join("\r\n") + "\r\n";
}

function markdownValue(value) {
  const escaped = String(value ?? "").replace(/\s*\r?\n\s*/g, " ").trim()
    .replace(/[&<>"\x60|\[\]*_~!\\]/g, char => "&#" + char.charCodeAt(0) + ";");
  return escaped || "Unavailable";
}

function caseBrief(packet, reference, selected) {
  const review = packet.case;
  const decision = packet.evidence["/case/decision"];
  const snapshot = packet.evidence[selected.snapshot_ref];
  const rows = [
    "# Review " + markdownValue(review.id), "",
    "| Field | Value |", "| --- | --- |",
    ...[
      ["Account", review.account_id], ["Repository", review.repository], ["Role under review", review.role],
      ["Evidence type", inputType(packet)], ["Reference snapshot", reference.snapshot], ["Reference time", reference.captured_at],
      ["Selected snapshot", selected.snapshot], ["Selected time", selected.captured_at], ["Outcome", verdicts[selected.verdict]],
      ["Reason", selected.reason], ["Decision time", decision.recorded_at], ["Reviewer", decision.reviewer],
      ["Decision rationale", decision.reason], ["Input SHA-256", packet.input_sha256],
    ].map(([label, value]) => "| " + label + " | " + markdownValue(value) + " |"),
  ];
  if (review.access_model === githubModel) {
    const lookup = snapshot.sources?.[githubSource]?.capture?.role_lookup;
    rows.push("| Reference effective role | " + markdownValue(reference.effective_role) + " |",
      "| Selected effective role | " + markdownValue(selected.effective_role) + " |",
      "| GitHub request ID | " + markdownValue(lookup?.request_id) + " |",
      "| Role lookup status | " + markdownValue(Number.isInteger(lookup?.status) ? "HTTP " + lookup.status : null) + " |");
  }
  rows.push("", "## Evidence coverage", "");
  if (Object.keys(selected.source_coverage).length) {
    rows.push("| Source | Coverage | File | SHA-256 |", "| --- | --- | --- | --- |");
    for (const [name, state] of Object.entries(selected.source_coverage)) {
      const path = selected.snapshot_ref + "/sources/" + name;
      const source = packet.provenance?.sources[path] ?? snapshot.sources?.[name];
      const label = Object.hasOwn(sources, name) ? sources[name].label : name;
      rows.push("| " + [label, coverageLabels[state], source?.file ?? source?.capture?.file, source?.sha256]
        .map(markdownValue).join(" | ") + " |");
    }
  } else {
    rows.push("Source coverage is unavailable for this snapshot.");
  }
  if (selected.paths.length) {
    rows.push("", "## Cited records", "");
    for (const path of selected.paths) {
      const name = path.team_id ? "Team grant via " + path.team_id : path.kind === "direct" ? "Direct grant" : "GitHub role";
      rows.push("- " + markdownValue(name) + " · " + path.evidence.map(markdownValue).join(", "));
    }
  }
  return rows.join("\n") + "\n";
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { comparePaths, filterReviews, inputType, reviewCsv, caseBrief, evidenceFingerprints, verifyEvidenceFiles };
}
