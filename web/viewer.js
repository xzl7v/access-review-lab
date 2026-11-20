"use strict";

const batchPriority = { still_granted: 0, inconclusive: 1, verified_removed: 2 };
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
  const github = review.access_model === githubModel;
  if (github) {
    requirePacket(isObject(review.github_scope) && ["github", "synthetic"].includes(review.github_scope.origin)
      && hasText(observations[0]?.effective_role),
      "The packet is missing the GitHub capture origin or baseline role.");
  }
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
      requirePacket(isObject(path) && (github ? path.kind === "effective"
        : path.kind === "direct" || (path.kind === "team" && hasText(path.team_id)))
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

const utcTime = new Intl.DateTimeFormat("en-GB", {
  timeZone: "UTC", day: "2-digit", month: "short", year: "numeric",
  hour: "2-digit", minute: "2-digit", hourCycle: "h23",
});
function timeLabel(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : utcTime.format(date) + " UTC";
}

function renderFields(container, fields) {
  container.replaceChildren(...fields.map(([label, value]) => {
    const field = element("div");
    field.append(element("dt", label), element("dd", String(value ?? "Unavailable")));
    return field;
  }));
}

function statusLabel(text, state) {
  const status = element("span", text, "status");
  status.dataset.state = state;
  return status;
}

function scopedSource(name) {
  return Object.hasOwn(sources, name) ? sources[name] : { label: humanize(name), record: "Source record" };
}

function showRecord(packet, title, reference, record) {
  byId("record-title").textContent = title;
  byId("record-reference").textContent = reference;
  const provenance = packet.packet_version === 2 ? packet.provenance : null;
  const location = provenance?.records[reference];
  const name = sourceName(reference);
  const source = provenance?.sources[location?.source_ref ?? reference];
  const metadata = [];
  if (source) {
    metadata.push(["CSV file", source.file],
      location ? ["CSV record", location.record_number] : ["CSV records", source.record_count],
      ["SHA-256", source.sha256]);
  }
  if (packet.case.access_model === githubModel && reference.endsWith("/sources/" + githubSource)
      && isObject(record.capture)) {
    const capture = record.capture;
    const lookup = capture.role_lookup;
    const user = lookup?.data?.user ?? capture.account_lookup?.data;
    metadata.push(
      ["Capture file", record.file], ["Repository ID", capture.repository_lookup?.data?.id],
      ["Account ID", user?.id], ["Role lookup", Number.isInteger(lookup?.status) ? "HTTP " + lookup.status : null],
      ["Request ID", lookup?.request_id], ["SHA-256", record.sha256],
    );
  } else if (isObject(record.capture)) {
    if (!source) metadata.push(["Capture file", record.capture.file]);
    metadata.push(["Capture time", record.capture.captured_at], ["Repository scope", record.capture.repository]);
  }
  if (reference === "/case/decision") {
    metadata.push(["Action", hasText(record.action) ? humanize(record.action) : null], ["Reviewer", record.reviewer],
      ["Recorded at", record.recorded_at], ["Rationale", record.reason]);
  } else if (reference.match(/^\/snapshots\/[0-9]+$/)) {
    metadata.push(["Capture time", record.captured_at], ["Repository scope", record.repository]);
  } else if (location || reference.includes("/rows/")) {
    const fields = scopedSource(name).fields ?? [];
    metadata.push(...fields.map(field => [humanize(field), record[field]]));
  } else if (!isObject(record.capture) && typeof record.complete === "boolean" && !source) {
    metadata.push(["Export marked complete", record.complete ? "Yes" : "No"],
      ["Rows", Array.isArray(record.rows) ? record.rows.length : null]);
  }
  const fields = byId("record-fields");
  fields.hidden = !metadata.length;
  renderFields(fields, metadata);
  const raw = byId("raw-record");
  raw.open = false;
  const data = byId("record-data");
  try {
    data.textContent = JSON.stringify(record, null, 2);
  } catch {
    data.textContent = "This record is too deeply nested to display.";
  }
  data.scrollTop = 0;
}

function focusInspector() {
  if (window.matchMedia("(max-width: 780px)").matches) byId("record-title").focus();
}

const changeLabels = {
  retained: "Still present", absent: "No longer observed", unresolved: "Unresolved", new: "Newly observed",
};

function showObservation(packet, referenceObservation, observation) {
  const result = byId("snapshot-result");
  result.textContent = verdicts[observation.verdict];
  result.dataset.state = observation.verdict;
  byId("snapshot-title").textContent = humanize(observation.snapshot);
  const time = byId("snapshot-time");
  time.textContent = timeLabel(observation.captured_at);
  time.dateTime = observation.captured_at;
  byId("snapshot-reason").textContent = observation.reason;
  const github = packet.case.access_model === githubModel;
  const comparison = byId("role-comparison");
  comparison.hidden = !github;
  if (github) {
    const showRole = item => hasText(item.effective_role) ? humanize(item.effective_role) : "Unresolved";
    renderFields(comparison, [["Reference role", showRole(referenceObservation)], ["Selected role", showRole(observation)]]);
  }
  byId("path-comparison").hidden = github;
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

  function recordButton(label, title, reference, record) {
    const button = element("button", label, "record-link");
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
      focusInspector();
    });
    return button;
  }

  if (!github) {
    const changes = comparePaths(packet, referenceObservation, observation);
    byId("path-table").hidden = !changes.length;
    byId("path-empty").hidden = changes.length > 0;
    for (const { path, observed, absent, state } of changes) {
      const title = path.kind === "direct" ? "Direct grant" : "Team grant via " + path.team_id;
      const row = element("tr");
      const status = element("td");
      status.append(statusLabel(changeLabels[state], state));
      const evidence = element("td");
      const controls = element("div", "", "record-controls");
      if (absent) {
        const name = scopedSource(absent).label;
        const reference = observation.snapshot_ref + "/sources/" + absent;
        controls.append(recordButton(name + " check", name, reference, exports[absent]));
      }
      for (const reference of (observed ?? path).evidence) {
        const name = scopedSource(sourceName(reference)).record;
        const label = observed ? name : "Reference " + name.toLowerCase();
        controls.append(recordButton(label, name, reference, packet.evidence[reference]));
      }
      evidence.append(controls);
      row.append(element("td", title), status, evidence);
      paths.append(row);
    }
  }

  for (const [name, state] of Object.entries(observation.source_coverage)) {
    const line = element("div", "", "source-item");
    const item = element("div");
    const title = scopedSource(name).label;
    const source = Object.hasOwn(exports, name) ? exports[name] : null;
    const reference = observation.snapshot_ref + "/sources/" + name;
    item.append(isObject(source) ? recordButton(title, title, reference, source) : element("span", title));
    const issue = observation.source_issues?.[name];
    if (hasText(issue?.reason)) item.append(element("p", [issue.file, issue.reason].filter(hasText).join(" · "), "source-issue"));
    line.append(item, statusLabel(coverageLabels[state], state));
    coverage.append(line);
  }
  if (!coverage.firstChild) coverage.append(element("p", "Source coverage is unavailable.", "supporting"));
  records.append(recordButton("Snapshot record", "Snapshot record", observation.snapshot_ref, snapshot));
  first();

  return () => {
    active?.setAttribute("aria-pressed", "false");
    active = null;
    showRecord(packet, "Review decision", "/case/decision", packet.evidence["/case/decision"]);
    focusInspector();
  };
}

function saveDownload(filename, content, type) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const link = document.createElement("a");
  link.download = filename;
  link.href = url;
  document.body.append(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function renderPacket(packet, selectedIndex) {
  const review = packet.case;
  const decision = packet.evidence["/case/decision"];
  byId("case-title").textContent = "Case " + review.id;
  const fields = [["Account", review.account_id], ["Repository", review.repository],
    ["Role under review", review.role], ["Evidence type", inputType(packet)]];
  if (review.access_model === githubModel) {
    fields.push(["Capture origin", review.github_scope.origin === "synthetic" ? "Synthetic data" : "GitHub REST API"]);
  }
  renderFields(byId("case-fields"), fields);
  const options = byId("snapshot-options");
  const comparison = byId("snapshot-reference");
  let selected = selectedIndex ?? Math.max(packet.observations.findIndex(item => item.verdict === "still_granted"), 0);
  let showDecision;
  const decisionButton = element("button", "", "snapshot-option decision-option");
  decisionButton.type = "button";
  decisionButton.setAttribute("aria-controls", "record-pane");

  function addTime(button, label, timestamp) {
    button.append(element("span", label));
    if (hasText(timestamp)) {
      const time = element("time", timeLabel(timestamp));
      time.dateTime = timestamp;
      button.append(time);
    }
  }

  const buttons = packet.observations.map((observation, index) => {
    const button = element("button", "", "snapshot-option");
    button.type = "button";
    addTime(button, humanize(observation.snapshot), observation.captured_at);
    button.addEventListener("click", () => {
      selected = index;
      showSelection();
    });
    return button;
  });
  comparison.replaceChildren(...packet.observations.map((observation, index) => {
    const option = element("option", humanize(observation.snapshot));
    option.value = String(index);
    return option;
  }));
  comparison.value = "0";
  comparison.onchange = showSelection;
  addTime(decisionButton, "Review decision", decision.recorded_at);
  decisionButton.addEventListener("click", () => showDecision());
  options.replaceChildren(buttons[0], decisionButton, ...buttons.slice(1));

  function showSelection() {
    buttons.forEach((button, index) => button.setAttribute("aria-pressed", String(index === selected)));
    showDecision = showObservation(packet, packet.observations[Number(comparison.value)], packet.observations[selected]);
  }

  byId("export-brief").onclick = () => {
    const id = review.id.replace(/[^a-z0-9_-]/gi, "-").slice(0, 80) || "review";
    const brief = caseBrief(packet, packet.observations[Number(comparison.value)], packet.observations[selected]);
    saveDownload(id + "-review.md", brief, "text/markdown;charset=utf-8");
  };
  showSelection();
  byId("packet-view").hidden = false;
}

function renderBatch(reviews) {
  const search = byId("batch-search");
  const rows = byId("batch-rows");
  const filters = byId("batch-filters");
  const exportButton = byId("export-queue");
  const states = ["all", ...Object.keys(batchPriority)];
  const filterButtons = new Map();
  let selected;
  let outcome = "all";
  let shown = [];

  function selectReview(review) {
    if (review === selected && !byId("packet-view").hidden) return;
    selected = review;
    renderPacket(review.packet, review.index);
  }

  function showMatchingReviews() {
    const query = search.value;
    const searchable = filterReviews(reviews, "all", query);
    shown = outcome === "all" ? searchable : searchable.filter(item => item.verdict === outcome);
    for (const [state, button] of filterButtons) {
      const count = state === "all" ? searchable.length : searchable.filter(item => item.verdict === state).length;
      const label = state === "all" ? "All" : verdicts[state];
      button.replaceChildren(document.createTextNode(label), element("span", String(count), "tab-count"));
      button.setAttribute("aria-label", label + " (" + count + (count === 1 ? " review)" : " reviews)"));
      button.setAttribute("aria-pressed", String(state === outcome));
    }
    if (shown.length) selectReview(shown.includes(selected) ? selected : shown[0]);
    else byId("packet-view").hidden = true;
    rows.replaceChildren(...shown.map(review => {
      const { id, account_id: account, repository } = review.packet.case;
      const item = review.packet.observations[review.index];
      const button = element("button", id, "case-link");
      button.type = "button";
      button.setAttribute("aria-controls", "packet-view");
      button.setAttribute("aria-current", String(review === selected));
      button.addEventListener("click", () => {
        selectReview(review);
        for (const row of rows.children) {
          const active = row.contains(button);
          row.dataset.selected = String(active);
          row.querySelector("button").setAttribute("aria-current", String(active));
        }
        byId("case-title").focus();
      });
      const caseCell = element("td");
      caseCell.append(button);
      const outcomeCell = element("td");
      outcomeCell.append(statusLabel(verdicts[review.verdict], review.verdict));
      const row = element("tr");
      row.dataset.selected = String(review === selected);
      row.append(caseCell, element("td", account, "medium"), element("td", repository),
        element("td", inputType(review.packet), "wide"), outcomeCell, element("td", timeLabel(item.captured_at), "wide"));
      return row;
    }));
    byId("batch-count").textContent = "Showing " + shown.length + " of " + reviews.length
      + (reviews.length === 1 ? " review" : " reviews");
    byId("batch-table").hidden = !shown.length;
    byId("batch-empty").hidden = shown.length > 0;
    exportButton.disabled = !shown.length;
  }

  filters.replaceChildren(...states.map(state => {
    const button = element("button");
    button.type = "button";
    button.addEventListener("click", () => {
      outcome = state;
      showMatchingReviews();
    });
    filterButtons.set(state, button);
    return button;
  }));
  search.value = "";
  search.oninput = showMatchingReviews;
  exportButton.onclick = () => saveDownload("access-reviews.csv", reviewCsv(shown), "text/csv;charset=utf-8");
  byId("batch-view").hidden = false;
  showMatchingReviews();
}

function openDocument(text, name, activeSample = null) {
  const payload = parseJson(text);
  let status;
  if (isObject(payload) && Object.hasOwn(payload, "batch_version")) {
    const reviews = validateBatch(payload);
    renderBatch(reviews);
    status = "Batch v" + payload.batch_version;
  } else {
    const packet = validatePacket(payload);
    byId("batch-view").hidden = true;
    byId("batch-search").oninput = null;
    byId("batch-rows").replaceChildren();
    renderPacket(packet);
    status = "Packet v" + packet.packet_version;
  }
  for (const [mode, sample] of Object.entries(sampleFiles)) {
    byId(sample.button).setAttribute("aria-pressed", String(mode === activeSample));
  }
  byId("load-status").textContent = name + " · " + status;
  byId("load-error").hidden = true;
}

function displayError(error) {
  const message = byId("load-error");
  message.textContent = error.message;
  message.hidden = false;
}

const sampleFiles = {
  batch: { button: "load-batch-sample", script: "sample-batch", title: "Sample queue" },
  csv: { button: "load-sample", script: "sample-packet", title: "CSV sample" },
  github: { button: "load-github-sample", script: "sample-github", title: "GitHub capture sample" },
};
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

function loadSample(mode) {
  request++;
  try {
    const { script, title } = sampleFiles[mode];
    const encoded = byId(script).textContent.trim();
    const bytes = Uint8Array.from(atob(encoded), character => character.charCodeAt(0));
    openDocument(new TextDecoder().decode(bytes), title, mode);
  } catch (error) {
    displayError(error);
  }
}

for (const [mode, sample] of Object.entries(sampleFiles)) {
  byId(sample.button).addEventListener("click", () => loadSample(mode));
}
const initialView = window.location.hash.slice(1);
loadSample(Object.hasOwn(sampleFiles, initialView) ? initialView : document.body.dataset.defaultView);
