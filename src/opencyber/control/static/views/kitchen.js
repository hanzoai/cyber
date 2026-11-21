// Full kitchen-sink surfaces: catalog, skills, security, SBOM, hardening, capture.

import { h, mount, api, badge, severity, status, table, fmt, input, select, emptyState } from "../lib.js";

function head(root, title, detail, actions) {
  mount(root, h("div", { class: "page-head" }, h("div", {}, h("h1", {}, title), h("p", {}, detail)), h("div", { class: "actions" }, actions || [])));
  const body = h("div", { class: "stack" });
  root.append(body);
  return body;
}

export async function renderTools(root) {
  const body = head(root, "Tools", "Every MCP tool advertised by this harness, plus engagement-scoped custom tools.", []);
  const search = input({ placeholder: "Search 271 tools", style: { width: "260px" } });
  const group = select([["", "All groups"]], { style: { width: "180px" } });
  const view = h("div");
  body.append(h("div", { class: "row wrap" }, search, group), view);

  const data = await api.get("/tools/catalog");
  for (const key of Object.keys(data.by_group || {}).sort()) {
    group.append(h("option", { value: key }, `${key} (${data.by_group[key]})`));
  }
  const draw = () => {
    const q = search.value.toLowerCase();
    const rows = (data.tools || []).filter((tool) => (!group.value || tool.group === group.value) && (!q || `${tool.name} ${tool.group} ${tool.shape}`.toLowerCase().includes(q)));
    mount(view, h("div", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "MCP catalog"), h("span", { class: "badge" }, `${Math.min(rows.length, 80)}/${data.total} shown`)),
      table([
        { label: "Tool", render: (row) => h("span", { class: "mono" }, row.name) },
        { label: "Kind", render: (row) => badge(row.kind) },
        { label: "Group", render: (row) => badge(row.group) },
        { label: "Shape", render: (row) => badge(row.shape) },
        { label: "Effects", render: (row) => h("div", { class: "chip-list" }, row.effects.map((effect) => h("span", { class: "chip" }, effect))) },
        { label: "Scope", render: (row) => badge(row.scope) },
        { label: "Engagement", render: (row) => row.requires_engagement ? badge("required", "warn") : "—" },
        { label: "Destructive", render: (row) => row.destructive ? badge("yes", "danger") : "no" },
      ], rows.slice(0, 80), { empty: "No tools match.", action: h("button", { class: "btn", onclick: () => { search.value = ""; group.value = ""; draw(); } }, "Clear filters") })));
  };
  search.addEventListener("input", draw);
  group.addEventListener("change", draw);
  draw();
}

export async function renderSkills(root) {
  const body = head(root, "Skills", "Operator-authored skills available to the agents, plus workspace skill files.", []);
  const data = await api.get("/skills");
  const skills = data.skills || [];
  mount(body,
    h("div", { class: "grid cols-4" },
      h("div", { class: "card stat" }, h("div", { class: "label" }, "Skills"), h("div", { class: "value" }, skills.length)),
      h("div", { class: "card stat" }, h("div", { class: "label" }, "Total uses"), h("div", { class: "value" }, fmt.n(skills.reduce((sum, item) => sum + Number(item.uses || 0), 0)))),
      h("div", { class: "card stat" }, h("div", { class: "label" }, "Workspace files"), h("div", { class: "value" }, (data.files || []).length)),
      h("div", { class: "card stat" }, h("div", { class: "label" }, "Tool calls"), h("div", { class: "value" }, fmt.n(data.calls))),
    ),
    h("div", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Registry"), h("span", { class: "badge" }, skills.length)), table([
      { label: "Skill", render: (row) => h("span", { class: "mono" }, row.name) },
      { label: "Purpose", render: (row) => row.description || "—" },
      { label: "Uses", num: true, render: (row) => fmt.n(row.uses || 0) },
      { label: "State", render: (row) => badge(row.status || "enabled", row.status === "enabled" ? "ok" : "") },
    ], skills, { empty: "No skills registered.", action: h("a", { class: "btn", href: "#/workspace" }, "Open workspace") })),
    h("div", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Workspace files")), h("div", { class: "card-body" }, h("div", { class: "chip-list" }, (data.files || []).map((file) => h("span", { class: "chip mono" }, file.path))))),
  );
}

export async function renderSecurity(root) {
  const body = head(root, "Secret scanning", "Credential-shape findings across the engagement; values are never stored.", []);
  const data = await api.get("/security");
  const rows = data.findings || [];
  const summary = data.summary || {};
  mount(body,
    h("div", { class: "grid cols-4" },
      h("div", { class: "card stat" }, h("div", { class: "label" }, "Findings"), h("div", { class: "value" }, summary.total || 0)),
      h("div", { class: "card stat" }, h("div", { class: "label" }, "Open"), h("div", { class: "value" }, summary.open || 0)),
      h("div", { class: "card stat" }, h("div", { class: "label" }, "Critical / high"), h("div", { class: "value" }, (summary.by_severity?.critical || 0) + (summary.by_severity?.high || 0))),
      h("div", { class: "card stat" }, h("div", { class: "label" }, "Upstream"), h("div", { class: "value", style: { fontSize: "12px", fontFamily: "var(--mono)" } }, (data.endpoint || "—").replace(/^https?:\/\//, "").slice(0, 32))),
    ),
    h("div", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Findings"), h("span", { class: "badge" }, rows.length)), table([
      { label: "Finding", render: (row) => h("span", { style: { fontWeight: 500 } }, row.name) },
      { label: "Kind", render: (row) => badge(row.kind) },
      { label: "Severity", render: (row) => severity(row.severity) },
      { label: "Location", render: (row) => h("span", { class: "mono faint", style: { fontSize: "11px" } }, row.location) },
      { label: "Source", render: (row) => badge(row.source) },
      { label: "State", render: (row) => status(row.status) },
      { label: "Evidence", render: (row) => h("span", { class: "muted" }, row.evidence || "—") },
    ], rows, { empty: "No secret findings.", action: h("a", { class: "btn", href: "#/tasks" }, "Start a scan task") })),
  );
}

export async function renderSbom(root) {
  const body = head(root, "SBOM", "Software bill of materials for the deployed harness and image.", []);
  const data = await api.get("/sbom");
  const rows = data.packages || [];
  const summary = data.summary || {};
  mount(body,
    h("div", { class: "grid cols-4" },
      h("div", { class: "card stat" }, h("div", { class: "label" }, "Packages"), h("div", { class: "value" }, summary.total || 0)),
      h("div", { class: "card stat" }, h("div", { class: "label" }, "With findings"), h("div", { class: "value" }, summary.findings || 0)),
      h("div", { class: "card stat" }, h("div", { class: "label" }, "Unknown license"), h("div", { class: "value" }, summary.unknown_license || 0)),
      h("div", { class: "card stat" }, h("div", { class: "label" }, "Upstream"), h("div", { class: "value", style: { fontSize: "12px", fontFamily: "var(--mono)" } }, (data.endpoint || "—").replace(/^https?:\/\//, "").slice(0, 32))),
    ),
    h("div", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Components"), h("span", { class: "badge" }, rows.length)), table([
      { label: "Package", render: (row) => h("span", { class: "mono" }, row.name) },
      { label: "Version", render: (row) => h("span", { class: "mono" }, row.version) },
      { label: "License", render: (row) => badge(row.license, row.license === "unknown" ? "warn" : "") },
      { label: "Risk", render: (row) => severity(row.severity) },
      { label: "State", render: (row) => status(row.status) },
      { label: "Source", render: (row) => badge(row.source) },
    ], rows, { empty: "No SBOM records.", action: h("a", { class: "btn", href: "#/settings" }, "Configure source") })),
  );
}

export async function renderHardening(root) {
  const body = head(root, "Linux hardening", "Packages, syscalls and services removed from the image, each with evidence.", []);
  const data = await api.get("/hardening");
  const rows = data.items || [];
  const summary = data.summary || {};
  mount(body,
    h("div", { class: "grid cols-4" },
      h("div", { class: "card stat" }, h("div", { class: "label" }, "Controls"), h("div", { class: "value" }, summary.total || 0)),
      h("div", { class: "card stat" }, h("div", { class: "label" }, "Removed"), h("div", { class: "value" }, summary.removed || 0)),
      h("div", { class: "card stat" }, h("div", { class: "label" }, "Disabled / blocked"), h("div", { class: "value" }, summary.disabled || 0)),
      h("div", { class: "card stat" }, h("div", { class: "label" }, "With evidence"), h("div", { class: "value" }, summary.with_evidence || 0)),
    ),
    h("div", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Baseline"), h("span", { class: "badge" }, rows.length)), table([
      { label: "Control", render: (row) => h("span", { style: { fontWeight: 500 } }, row.name) },
      { label: "Type", render: (row) => badge(row.kind) },
      { label: "Action", render: (row) => badge(row.action, row.action === "removed" ? "danger" : "warn") },
      { label: "Rationale", render: (row) => h("span", { class: "muted" }, (row.note || "—").slice(0, 90)) },
      { label: "Evidence", render: (row) => h("span", { class: "mono faint", style: { fontSize: "11px" } }, (row.evidence || "—").slice(0, 44)) },
      { label: "State", render: (row) => badge(row.status || "verified", "ok") },
    ], rows, { empty: "No hardening controls recorded.", action: h("a", { class: "btn", href: "#/docs" }, "Open baseline doc") })),
  );
}

export async function renderScanner(root) {
  const body = head(root, "Capture & scanner", "Traffic conversations and discovered hosts/ports in one working view.", []);
  const [packetsData, hostsData] = await Promise.all([api.get("/packets"), api.get("/hosts")]);
  const packets = packetsData.packets || [];
  const hosts = hostsData.hosts || [];
  const filter = input({ placeholder: "Display filter (host, method, status)", style: { width: "300px" } });
  const tabs = h("div", { class: "tabs" }, h("button", { class: "tab active" }, `Packets (${packets.length})`), h("button", { class: "tab" }, `Hosts & ports (${hosts.length})`));
  const view = h("div");
  body.append(h("div", { class: "row wrap" }, filter), tabs, view);
  const drawPackets = () => {
    const q = filter.value.toLowerCase();
    const rows = packets.filter((row) => !q || `${row.source} ${row.method} ${row.url} ${row.status}`.toLowerCase().includes(q));
    mount(view, h("div", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Packet list"), h("span", { class: "badge" }, `${rows.length}/${packets.length}`)), table([
      { label: "No.", num: true, render: (row) => h("span", { class: "mono faint" }, String(row.id).slice(-6)) },
      { label: "Time", render: (row) => h("span", { class: "mono faint" }, String(row.time || "").slice(11, 19)) },
      { label: "Source", render: (row) => h("span", { class: "mono" }, row.source) },
      { label: "Destination", render: (row) => h("span", { class: "mono" }, row.destination) },
      { label: "Protocol", render: (row) => badge(row.protocol) },
      { label: "Length", num: true, render: (row) => fmt.bytes(row.length) },
      { label: "Info", render: (row) => h("a", { class: "mono", href: "#/traffic" }, String(row.info).slice(0, 80)) },
    ], rows, { empty: "No packets captured.", action: h("a", { class: "btn", href: "#/traffic" }, "Import HAR") })));
  };
  const drawHosts = () => mount(view, h("div", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Hosts & ports"), h("span", { class: "badge" }, hosts.length)), table([
    { label: "Host", render: (row) => h("span", { class: "mono" }, row.host) },
    { label: "Kind", render: (row) => badge(row.kind) },
    { label: "Ports", render: (row) => h("div", { class: "chip-list" }, (row.ports || []).map((port) => h("span", { class: "chip mono" }, String(port)))) },
    { label: "Services", render: (row) => h("div", { class: "chip-list" }, (row.services || []).map((service) => h("span", { class: "chip" }, service))) },
    { label: "State", render: (row) => badge(row.state, row.state === "up" ? "ok" : "") },
    { label: "Source", render: (row) => (row.sources || []).join(", ") || "—" },
  ], hosts, { empty: "No hosts discovered.", action: h("button", { class: "btn", onclick: () => { location.hash = "#/assets"; } }, "Add asset") })));
  tabs.children[0].onclick = () => { tabs.children[0].classList.add("active"); tabs.children[1].classList.remove("active"); drawPackets(); };
  tabs.children[1].onclick = () => { tabs.children[1].classList.add("active"); tabs.children[0].classList.remove("active"); drawHosts(); };
  filter.addEventListener("input", drawPackets);
  drawPackets();
}
