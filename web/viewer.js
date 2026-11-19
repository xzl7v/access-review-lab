"use strict";

const verdicts = {
  detected: "Access detected",
  still_granted: "Still granted",
  verified_removed: "Verified removed",
  inconclusive: "Needs evidence",
};
const batchPriority = { still_granted: 0, inconclusive: 1, verified_removed: 2 };
const coverageLabels = { complete: "Complete", partial: "Partial", missing: "Missing" };
const sourceLabels = {
  direct_grants: ["Direct grant", "Direct grants"],
  team_memberships: ["Team membership", "Team memberships"],
  team_grants: ["Team grant", "Team grants"],
  team_links: ["Team link", "Team links"],
};
const byId = id => document.getElementById(id);
const isObject = value => value !== null && typeof value === "object" && !Array.isArray(value);
const hasText = value => typeof value === "string" && value.trim() !== "";
const isHash = value => typeof value === "string" && /^[a-f0-9]{64}$/.test(value);

function requirePacket(condition, message) {
  if (!condition) throw new Error(message);
}

function parseJson(text) {
  try {
    return JSON.parse(text.replace(/^\uFEFF/, ""));
  } catch {
    throw new Error("The selected file does not contain valid JSON.");
  }
}

function validatePacket(packet) {
  requirePacket(isObject(packet) && [1, 2].includes(packet.packet_version),
    "Choose an Access Review Lab evidence packet in version 1 or 2.");
  const { case: review, evidence, observations } = packet;
  requirePacket(isObject(review) && ["id", "account_id", "repository", "role"].every(key => hasText(review[key]))
    && isHash(packet.input_sha256),
    "The packet is missing its case details or input fingerprint.");
  requirePacket(isObject(evidence) && isObject(evidence["/case/decision"])
    && Array.isArray(observations) && observations.length > 0,
    "The packet needs observations and decision evidence.");
  const citedRecords = new Set();

  for (const [index, observation] of observations.entries()) {
    requirePacket(isObject(observation) && hasText(observation.snapshot)
      && hasText(observation.captured_at) && hasText(observation.reason)
      && observation.snapshot_ref === "/snapshots/" + index
      && hasText(observation.verdict) && Object.hasOwn(verdicts, observation.verdict)
      && Object.hasOwn(evidence, observation.snapshot_ref) && isObject(evidence[observation.snapshot_ref])
      && isObject(observation.source_coverage)
      && Object.values(observation.source_coverage).every(state => hasText(state) && Object.hasOwn(coverageLabels, state))
      && Array.isArray(observation.paths), "The packet contains an incomplete snapshot.");
    for (const path of observation.paths) {
      requirePacket(isObject(path) && (path.kind === "direct" || (path.kind === "team" && hasText(path.team_id)))
        && Array.isArray(path.evidence) && path.evidence.length > 0,
        "The packet contains an incomplete access path.");
      for (const reference of path.evidence) {
        requirePacket(hasText(reference) && reference.startsWith(observation.snapshot_ref + "/sources/")
          && Object.hasOwn(evidence, reference) && isObject(evidence[reference]),
          "The packet is missing a record cited by an access path.");
        citedRecords.add(reference);
      }
    }
  }

  if (packet.packet_version === 2) {
    const provenance = packet.provenance;
    requirePacket(isObject(provenance) && isObject(provenance.sources) && isObject(provenance.records),
      "The version 2 packet needs CSV provenance.");
    requirePacket(Object.values(provenance.sources).every(source => isObject(source)
      && hasText(source.file) && isHash(source.sha256)
      && Number.isSafeInteger(source.record_count) && source.record_count >= 0),
      "The packet contains an invalid CSV source.");
    for (const [reference, record] of Object.entries(provenance.records)) {
      requirePacket(isObject(record) && hasText(record.source_ref) && Object.hasOwn(provenance.sources, record.source_ref)
        && Number.isSafeInteger(record.record_number) && record.record_number >= 1
        && record.record_number <= provenance.sources[record.source_ref].record_count
        && reference === record.source_ref + "/rows/" + (record.record_number - 1),
        "A cited record has an invalid CSV location.");
    }
    for (const reference of citedRecords) {
      requirePacket(Object.hasOwn(provenance.records, reference),
        "A cited record is missing its CSV location.");
    }
  }
  return packet;
}

function validateBatch(batch) {
  requirePacket(batch.batch_version === 1 && Array.isArray(batch.reviews) && batch.reviews.length > 0,
    "Choose a version 1 batch file containing at least one review.");
  const seen = new Set();
  const reviews = batch.reviews.map(entry => {
    requirePacket(isObject(entry) && hasText(entry.follow_up), "A batch review is missing its follow-up.");
    const packet = validatePacket(entry.packet);
    const matches = packet.observations.filter(observation => observation.snapshot === entry.follow_up);
    const index = packet.observations.indexOf(matches[0]);
    requirePacket(matches.length === 1 && index > 0 && Object.hasOwn(batchPriority, matches[0].verdict),
      "A batch review has an invalid follow-up snapshot.");
    requirePacket(!seen.has(packet.case.id), "A batch file contains a duplicate case ID.");
    seen.add(packet.case.id);
    return { packet, index, verdict: matches[0].verdict };
  });
  return reviews.sort((left, right) => batchPriority[left.verdict] - batchPriority[right.verdict]);
}

function element(tag, text = "", className = "") {
  const item = document.createElement(tag);
  item.textContent = text;
  item.className = className;
  return item;
}

function humanize(value) {
  const words = value.replace(/[-_]+/g, " ");
  return words.charAt(0).toUpperCase() + words.slice(1);
}

function renderFields(container, fields) {
  container.replaceChildren(...fields.map(([label, value]) => {
    const field = element("div");
    field.append(element("dt", label), element("dd", value));
    return field;
  }));
}

function showRecord(packet, title, reference, record) {
  byId("record-title").textContent = title;
  byId("record-reference").textContent = reference;
  const provenance = packet.packet_version === 2 ? packet.provenance : null;
  const location = provenance?.records[reference];
  const source = provenance?.sources[location?.source_ref ?? reference];
  const fields = byId("record-fields");
  fields.hidden = !source;
  renderFields(fields, source ? [
    ["CSV file", source.file],
    location ? ["CSV record", String(location.record_number)] : ["CSV records", String(source.record_count)],
    ["SHA-256", source.sha256],
  ] : []);

  const data = byId("record-data");
  try {
    data.textContent = JSON.stringify(record, null, 2);
  } catch {
    data.textContent = "This record is too deeply nested to display.";
  }
  data.scrollTop = 0;
}

function showObservation(packet, observation) {
  const result = byId("snapshot-result");
  result.textContent = verdicts[observation.verdict];
  result.dataset.verdict = observation.verdict;
  byId("snapshot-title").textContent = humanize(observation.snapshot);
  const time = byId("snapshot-time");
  time.textContent = observation.captured_at;
  time.dateTime = observation.captured_at;
  byId("snapshot-reason").textContent = observation.reason;
  const paths = byId("access-paths");
  const coverage = byId("source-coverage");
  const records = byId("snapshot-records");
  paths.replaceChildren();
  coverage.replaceChildren();
  records.replaceChildren();
  const snapshot = packet.evidence[observation.snapshot_ref];
  const exports = isObject(snapshot.sources) ? snapshot.sources : {};
  let active;
  let first;

  function recordButton(title, reference, record) {
    const button = element("button", title, "record-option");
    button.type = "button";
    button.setAttribute("aria-controls", "record-pane");
    button.setAttribute("aria-pressed", "false");
    function select() {
      active?.setAttribute("aria-pressed", "false");
      active = button;
      button.setAttribute("aria-pressed", "true");
      showRecord(packet, title, reference, record);
    }
    first ??= select;
    button.addEventListener("click", () => {
      select();
      if (window.matchMedia("(max-width: 1050px)").matches) {
        byId("record-pane").scrollIntoView({ block: "nearest" });
      }
    });
    return button;
  }

  for (const path of observation.paths) {
    const group = element("div", "", "path");
    const title = path.kind === "direct" ? "Direct grant" : "Team grant via " + path.team_id;
    const steps = element("ol");
    for (const reference of path.evidence) {
      const name = reference.split("/")[4];
      const label = Object.hasOwn(sourceLabels, name) ? sourceLabels[name][0] : "Source record";
      const step = element("li");
      step.append(recordButton(label, reference, packet.evidence[reference]));
      steps.append(step);
    }
    group.append(element("h3", title), steps);
    paths.append(group);
  }
  if (!paths.firstChild) paths.append(element("p", "No grant paths observed.", "quiet"));

  for (const [name, state] of Object.entries(observation.source_coverage)) {
    const row = element("div", "", "coverage-item");
    const title = Object.hasOwn(sourceLabels, name) ? sourceLabels[name][1] : humanize(name);
    const status = element("span", coverageLabels[state], "coverage-state");
    status.dataset.state = state;
    const source = Object.hasOwn(exports, name) ? exports[name] : null;
    const reference = observation.snapshot_ref + "/sources/" + name;
    row.append(isObject(source) ? recordButton(title, reference, source) : element("span", title), status);
    coverage.append(row);
  }
  if (!coverage.firstChild) coverage.append(element("p", "Source coverage unavailable for this snapshot.", "quiet"));

  records.append(
    recordButton("Snapshot record", observation.snapshot_ref, snapshot),
    recordButton("Review decision", "/case/decision", packet.evidence["/case/decision"]),
  );
  first();
}

function renderPacket(packet, selectedIndex) {
  byId("case-title").textContent = "Case " + packet.case.id;
  renderFields(byId("case-fields"), [
    ["Account", packet.case.account_id],
    ["Repository", packet.case.repository],
    ["Role", packet.case.role],
  ]);
  const options = byId("snapshot-options");
  const buttons = packet.observations.map((observation, index) => {
    const button = element("button", humanize(observation.snapshot), "snapshot-option");
    button.type = "button";
    button.setAttribute("aria-pressed", "false");
    const time = element("time", observation.captured_at);
    time.dateTime = observation.captured_at;
    button.append(time);
    button.addEventListener("click", () => selectSnapshot(index));
    return button;
  });

  function selectSnapshot(index) {
    buttons.forEach((button, position) => button.setAttribute("aria-pressed", String(position === index)));
    showObservation(packet, packet.observations[index]);
  }
  options.replaceChildren(...buttons);
  selectSnapshot(selectedIndex ?? Math.max(
    packet.observations.findIndex(observation => observation.verdict === "still_granted"), 0,
  ));
  byId("packet-view").hidden = false;
}

function renderBatch(reviews) {
  const filter = byId("batch-filter");
  const rows = byId("batch-rows");
  const buttons = new Map();
  let selected = reviews[0];

  function selectReview(review) {
    selected = review;
    for (const [entry, button] of buttons) {
      button.setAttribute("aria-pressed", String(entry === review));
    }
    renderPacket(review.packet, review.index);
  }

  function showMatchingReviews() {
    const matches = reviews.filter(review => filter.value === "all" || review.verdict === filter.value);
    const hasResults = matches.length > 0;
    rows.replaceChildren();
    buttons.clear();
    for (const review of matches) {
      const { id, account_id: account, repository, role } = review.packet.case;
      const button = element("button", id, "batch-case");
      button.type = "button";
      button.setAttribute("aria-controls", "packet-view");
      button.addEventListener("click", () => {
        selectReview(review);
        byId("case-title").scrollIntoView({ block: "nearest" });
      });
      buttons.set(review, button);
      const caseCell = element("td");
      caseCell.append(button);
      const outcome = element("span", verdicts[review.verdict], "result");
      outcome.dataset.verdict = review.verdict;
      const resultCell = element("td");
      resultCell.append(outcome);
      const row = element("tr");
      row.append(caseCell, element("td", account, "batch-detail"), element("td", repository),
        element("td", role, "batch-detail"), resultCell);
      rows.append(row);
    }
    byId("batch-count").textContent = "Showing " + matches.length + " of " + reviews.length
      + (reviews.length === 1 ? " case" : " cases");
    byId("batch-table").hidden = !hasResults;
    byId("batch-empty").hidden = hasResults;
    if (hasResults) selectReview(matches.includes(selected) ? selected : matches[0]);
    else byId("packet-view").hidden = true;
  }

  filter.value = "all";
  filter.onchange = showMatchingReviews;
  byId("batch-view").hidden = false;
  showMatchingReviews();
}

function openDocument(text, name) {
  const payload = parseJson(text);
  let status;
  if (isObject(payload) && Object.hasOwn(payload, "batch_version")) {
    const reviews = validateBatch(payload);
    renderBatch(reviews);
    status = "Batch v" + payload.batch_version;
  } else {
    const packet = validatePacket(payload);
    byId("batch-view").hidden = true;
    byId("batch-filter").onchange = null;
    byId("batch-rows").replaceChildren();
    renderPacket(packet);
    status = "Packet v" + packet.packet_version;
  }
  byId("load-status").textContent = name + " · " + status;
  byId("load-error").hidden = true;
}

function displayError(error) {
  const message = byId("load-error");
  message.textContent = error.message;
  message.hidden = false;
}

const picker = byId("packet-file");
let request = 0;
byId("open-packet").addEventListener("click", () => picker.click());
picker.addEventListener("change", async () => {
  const file = picker.files[0];
  if (!file) return;
  picker.value = "";
  const selected = ++request;
  try {
    const text = await file.text();
    if (selected === request) openDocument(text, file.name);
  } catch (error) {
    if (selected === request) displayError(error);
  }
});

function loadSample(id, name) {
  request++;
  try {
    const encoded = byId(id).textContent.trim();
    const bytes = Uint8Array.from(atob(encoded), character => character.charCodeAt(0));
    openDocument(new TextDecoder().decode(bytes), name);
  } catch (error) {
    displayError(error);
  }
}

const loadSampleReview = () => loadSample("sample-packet", "Sample packet");
const loadSampleBatch = () => loadSample("sample-batch", "Sample batch");
byId("load-sample").addEventListener("click", loadSampleReview);
byId("load-batch-sample").addEventListener("click", loadSampleBatch);
if (window.location.hash === "#batch") loadSampleBatch();
else loadSampleReview();
