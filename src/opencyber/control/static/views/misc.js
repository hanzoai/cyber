// Engagement-level views: assets, command ledger, usage, workspace, sync and templates.

import {
  h, mount, api, badge, status, table, fmt, toast, drawer, confirmDialog, field,
  input, textarea, select, code, kv, emptyState, promptDialog, download, every,
} from "../lib.js";
import { assetTree } from "../graph.js";

const KINDS = ["root_domain", "subdomain", "host", "ip", "cidr", "url", "service", "port", "endpoint", "repository", "cloud_account"];

export async function renderAssets(root, ctx) {
  const body = h("div", { class: "stack" });
  mount(root, h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Assets"), h("p", {}, "One shared, deduplicated asset graph per engagement. Tasks anchor to assets; they never own them.")), h("div", { class: "actions" }, h("button", { class: "btn primary", onclick: () => addAssets(draw) }, "Add assets"))), body);

  const search = input({ placeholder: "Search assets (kind, value, property)", style: { width: "280px" }, oninput: () => draw() });
  const kindFilter = select([["", "All kinds"], ...KINDS.map((item) => [item, item])], { style: { width: "170px" }, onchange: () => draw() });
  const layout = h("div", { class: "split wide" });
  body.append(h("div", { class: "row" }, search, kindFilter), layout);

  let selected = null;
  async function draw() {
    const q = search.value.trim();
    const url = q ? "/assets/search?q=" + encodeURIComponent(q) : "/assets?kind=" + encodeURIComponent(kindFilter.value);
    const payload = await api.get(url, { limit: 500 });
    const rows = payload.assets || [];
    const tree = payload.tree || await api.get("/assets").then((value) => value.tree || { roots: [] }).catch(() => ({ roots: [] }));
    const detail = h("div", { class: "pane-right" });
    mount(
      layout,
      h("div", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Graph"), h("span", { class: "badge" }, payload.total ?? rows.length)), h("div", { class: "card-body" }, assetTree(tree, { selected: selected?.id, onSelect: async (entry) => { selected = await api.get("/assets/" + entry.id); draw(); } }))),
      detail,
    );
    if (selected) {
      const linkedIntents = selected.intents || [];
      const linkedFindings = selected.findings || [];
      mount(detail, h("div", { class: "stack" },
        h("div", { class: "row wrap" }, badge(selected.kind), h("span", { class: "mono", style: { fontSize: "13px" } }, selected.value)),
        kv([
          ["ID", h("span", { class: "mono" }, selected.id)],
          ["Sources", (selected.sources || []).join(", ") || "—"],
          ["Parent", selected.parent_id || "—"],
          ["Children", selected.children?.length || 0],
          ["Intents", linkedIntents.length],
          ["Findings", linkedFindings.length],
          ["Properties", selected.props ? code(selected.props) : "—"],
        ]),
        h("div", { class: "row" }, h("button", { class: "btn danger", onclick: async () => { if (await confirmDialog("Delete this asset and detach all anchors?", { danger: true, confirmLabel: "Delete" })) { await api.del("/assets/" + selected.id); selected = null; draw(); } } }, "Delete")),
      ));
    } else {
      mount(detail, h("div", { class: "empty-state" }, h("strong", {}, "Select an asset"), "Assets are created by workers, imports or operators. They are deduplicated by kind and value."));
    }
  }

  function addAssets(redraw) {
    const kind = select(KINDS, { value: "subdomain" });
    const values = textarea({ placeholder: "app.acme.test\napi.acme.test", style: { minHeight: "120px" } });
    drawer({ title: "Add assets", body: h("div", { class: "stack" }, field("Kind", kind), field("Values", values, "One per line; duplicates are merged.")), footer: [h("button", { class: "btn", onclick: () => document.getElementById("overlay").replaceChildren() }, "Cancel"), h("button", { class: "btn primary", onclick: async () => { try { await api.post("/assets", { assets: values.value.split("\n").map((value) => value.trim()).filter(Boolean).map((value) => ({ kind: kind.value, value })) }); toast("Assets added"); document.getElementById("overlay").replaceChildren(); redraw(); } catch (error) { toast(error.message, "error"); } } }, "Add")] });
  }

  await draw();
  ctxCleanup(root, draw);
}

export async function renderExecutions(root) {
  const body = h("div", { class: "stack" });
  mount(root, h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Commands"), h("p", {}, "Every tool call, its arguments, its outcome and its duration.")), h("div", { class: "actions" }, h("a", { class: "btn", href: "#/llm-records" }, "LLM records"))), body);
  const search = input({ placeholder: "Search tool or arguments", style: { width: "260px" }, oninput: () => draw() });
  const tool = input({ placeholder: "tool name", style: { width: "180px" }, oninput: () => draw() });
  const state = select([["", "Any outcome"], ["succeeded", "Succeeded"], ["failed", "Failed"], ["denied", "Denied"]], { style: { width: "150px" }, onchange: () => draw() });
  const summary = h("div", { class: "grid cols-4" });
  const list = h("div");
  body.append(h("div", { class: "row wrap" }, search, tool, state), summary, list);

  async function draw() {
    const [payload, stats] = await Promise.all([
      api.get("/executions", { search: search.value, tool: tool.value, status: state.value, limit: 100 }),
      api.get("/executions?stats=1"),
    ]);
    mount(summary,
      h("div", { class: "card stat" }, h("div", { class: "label" }, "Calls"), h("div", { class: "value" }, fmt.n(stats.total))),
      h("div", { class: "card stat" }, h("div", { class: "label" }, "Failed / denied"), h("div", { class: "value" }, fmt.n(stats.failed))),
      h("div", { class: "card stat" }, h("div", { class: "label" }, "Distinct tools"), h("div", { class: "value" }, Object.keys(stats.by_tool || {}).length)),
      h("div", { class: "card stat" }, h("div", { class: "label" }, "Tracked"), h("div", { class: "value" }, fmt.n((payload.records || []).length))),
    );
    mount(list, h("div", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Executions")), table([
      { label: "Tool", render: (row) => h("span", { class: "mono" }, row.tool) },
      { label: "Arguments", render: (row) => h("span", { class: "mono faint", style: { fontSize: "11px" } }, JSON.stringify(row.arguments || {}).slice(0, 110)) },
      { label: "Outcome", render: (row) => status(row.status) },
      { label: "Duration", num: true, render: (row) => row.duration_ms ? row.duration_ms + "ms" : "—" },
      { label: "Task", render: (row) => (row.task_id ? h("a", { class: "mono", href: "#/tasks/" + row.task_id }, row.task_id.slice(0, 10)) : "—") },
      { label: "When", render: (row) => fmt.ago(row.created) },
    ], payload.records || [], { empty: "No executions recorded." })));
  }
  await draw();
}

export async function renderUsage(root) {
  const body = h("div", { class: "stack" });
  mount(root, h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "LLM records"), h("p", {}, "Every model call with token accounting, cache hits and per-model totals."))), body);
  const payload = await api.get("/usage", { days: 30 });
  const usage = payload.summary || {};
  const records = payload.records || [];
  mount(body,
    h("div", { class: "grid cols-5" },
      h("div", { class: "card stat" }, h("div", { class: "label" }, "Calls"), h("div", { class: "value" }, fmt.n(usage.calls))),
      h("div", { class: "card stat" }, h("div", { class: "label" }, "Input tokens"), h("div", { class: "value" }, fmt.n(usage.input_tokens))),
      h("div", { class: "card stat" }, h("div", { class: "label" }, "Output tokens"), h("div", { class: "value" }, fmt.n(usage.output_tokens))),
      h("div", { class: "card stat" }, h("div", { class: "label" }, "Cache hit"), h("div", { class: "value" }, fmt.pct(usage.cache_hit_rate || 0))),
      h("div", { class: "card stat" }, h("div", { class: "label" }, "By model"), h("div", { class: "value" }, (usage.by_model || []).length)),
    ),
    h("div", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "By model")), table([
      { label: "Model", render: (row) => h("span", { class: "mono" }, row.model) },
      { label: "Calls", num: true, key: "calls" },
      { label: "Input", num: true, render: (row) => fmt.n(row.input_tokens) },
      { label: "Output", num: true, render: (row) => fmt.n(row.output_tokens) },
      { label: "Cache read", num: true, render: (row) => fmt.n(row.cache_read) },
    ], usage.by_model || [])),
    h("div", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Recent calls")), table([
      { label: "Model", render: (row) => h("span", { class: "mono" }, row.model) },
      { label: "Input", num: true, render: (row) => fmt.n(row.input_tokens) },
      { label: "Output", num: true, render: (row) => fmt.n(row.output_tokens) },
      { label: "Cache", num: true, render: (row) => fmt.n(row.cache_read) },
      { label: "Latency", num: true, render: (row) => row.latency_ms ? row.latency_ms + "ms" : "—" },
      { label: "Task", render: (row) => (row.task_id ? h("a", { class: "mono", href: "#/tasks/" + row.task_id }, row.task_id.slice(0, 10)) : "—") },
      { label: "When", render: (row) => fmt.ago(row.created) },
    ], records, { empty: "No calls recorded." })),
    h("div", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Daily")), h("div", { class: "card-body" }, h("div", { class: "grid cols-4" }, (payload.daily || []).slice(-30).map((day) => h("div", { class: "chip" }, `${day.date}: ${fmt.n(day.input + day.output)}`))))),
  );
}

export async function renderSync(root) {
  const body = h("div", { class: "stack" });
  mount(root, h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Sync"), h("p", {}, "Import assets from an external source into this engagement's asset graph."))), body);
  const payload = await api.get("/sync/status");
  const source = input({ placeholder: "sync" });
  const values = textarea({ placeholder: "subdomain,app.acme.test\nip,10.0.0.5", style: { minHeight: "140px" } });
  mount(body,
    h("div", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "State")), h("div", { class: "card-body" }, kv([
      ["Configured", payload.configured ? "yes" : "no"],
      ["Enabled", payload.enabled ? "yes" : "no"],
      ["Target", payload.target || "—"],
      ["Tools", (payload.tools || []).join(", ") || "—"],
    ]))),
    h("div", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Import")), h("div", { class: "card-body stack" }, field("Source label", source), field("Assets (kind,value per line)", values), h("button", { class: "btn primary", onclick: async () => {
      const assets = values.value.split("\n").map((line) => line.trim()).filter(Boolean).map((line) => { const [kind, value] = line.split(",").map((item) => item.trim()); return { kind, value }; });
      try { const result = await api.post("/sync/import", { source: source.value, assets }); toast(`Imported ${result.imported} assets`); } catch (error) { toast(error.message, "error"); }
    } }, "Import"))),
  );
}

export async function renderWorkspace(root) {
  const body = h("div", { class: "stack" });
  mount(root, h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Workspace"), h("p", {}, "Engagement-scoped files. Paths are confined to this engagement; no host paths are accepted."))), body);
  const pathInput = input({ value: ".", style: { width: "360px" } });
  const list = h("div");
  const viewer = h("div", { class: "pane-right" }, h("div", { class: "empty-state" }, h("strong", {}, "No file selected")));
  const layout = h("div", { class: "split wide" });
  body.append(h("div", { class: "row" }, pathInput, h("button", { class: "btn", onclick: () => { current = pathInput.value || "."; draw(); } }, "Open"), h("button", { class: "btn", onclick: () => mkdir() }, "New folder")), layout);
  let current = ".";
  let file = "";

  async function draw() {
    let payload;
    try {
      payload = await api.get("/workspace", { path: current });
    } catch (error) {
      mount(list, h("div", { class: "alert danger" }, error.message));
      return;
    }
    mount(layout,
      h("div", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Files"), h("span", { class: "mono faint", style: { fontSize: "11px" } }, payload.workspace)), h("div", { class: "list" },
        (payload.entries || []).map((entry) => h("div", { class: "list-item", onclick: async () => {
          if (entry.type === "directory") { current = entry.path; pathInput.value = current; draw(); return; }
          file = entry.path;
          const content = await api.get("/workspace/file", { path: file });
          showFile(content);
        } }, h("div", { class: "row", style: { justifyContent: "space-between" } }, h("span", { class: "title mono" }, entry.path.split("/").pop()), badge(entry.type === "directory" ? "dir" : fmt.bytes(entry.size))))),
      )),
      viewer,
    );
  }

  function showFile(content) {
    const editor = textarea({ value: content.content, style: { minHeight: "420px", fontFamily: "var(--mono)", fontSize: "11.5px" } });
    mount(viewer, h("div", { class: "stack" }, h("div", { class: "row wrap" }, h("span", { class: "mono" }, file), content.truncated ? badge("truncated", "warn") : null, h("button", { class: "btn sm", onclick: async () => { const response = await api.download("/workspace/file", { path: file, download: "1" }); download(await response.blob(), file.split("/").pop()); } }, "Download")), editor, h("div", { class: "row" }, h("button", { class: "btn primary", onclick: async () => { try { await api.put("/workspace/file", { path: file, content: editor.value }); toast("Saved"); } catch (error) { toast(error.message, "error"); } } }, "Save"), h("button", { class: "btn ghost danger", onclick: async () => { if (await confirmDialog(`Delete ${file}?`, { danger: true, confirmLabel: "Delete" })) { await api.del("/workspace/file", undefined, { path: file }); file = ""; draw(); } } }, "Delete"))));
  }

  async function mkdir() {
    const name = await promptDialog({ title: "New folder", label: "Name", placeholder: "notes" });
    if (!name) return;
    const path = [current === "." ? "" : current, name].filter(Boolean).join("/");
    try { await api.post("/workspace/mkdir", { path }); draw(); } catch (error) { toast(error.message, "error"); }
  }

  await draw();
}

export async function renderTemplates(root) {
  const body = h("div", { class: "stack" });
  mount(root, h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Templates"), h("p", {}, "Reusable task goals, descriptions and approval rules.")), h("div", { class: "actions" }, h("a", { class: "btn", href: "#/tasks" }, "Tasks"), h("button", { class: "btn primary", onclick: () => edit(null, draw) }, "New template"))), body);
  async function draw() {
    const payload = await api.get("/templates");
    mount(body, h("div", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Templates")), table([
      { label: "Name", key: "name" },
      { label: "Category", render: (row) => row.category ? badge(row.category) : "—" },
      { label: "Goal", render: (row) => h("span", { class: "muted" }, (row.goal || "").slice(0, 110)) },
      { label: "Rules", num: true, render: (row) => (row.rules || []).length },
      { label: "", class: "actions-cell", render: (row) => h("div", { class: "row", style: { justifyContent: "flex-end" } }, h("button", { class: "btn sm", onclick: () => edit(row, draw) }, "Edit"), h("button", { class: "btn sm ghost danger", onclick: async () => { await api.del("/templates/" + row.id); draw(); } }, "Delete")) },
    ], payload.templates || [], { empty: "No templates. Create one from a task goal you repeat." })));
  }
  function edit(template, redraw) {
    const name = input({ value: template?.name || "" });
    const category = input({ value: template?.category || "" });
    const goal = textarea({ value: template?.goal || "", placeholder: "The task goal" });
    const description = textarea({ value: template?.description || "" });
    const rules = textarea({ value: JSON.stringify(template?.rules || [], null, 2), style: { fontFamily: "var(--mono)" } });
    drawer({ title: template ? "Edit template" : "New template", body: h("div", { class: "stack" }, h("div", { class: "form-grid" }, field("Name", name), field("Category", category)), field("Goal", goal), field("Description", description), field("Rules (JSON)", rules)), footer: [h("button", { class: "btn", onclick: () => document.getElementById("overlay").replaceChildren() }, "Cancel"), h("button", { class: "btn primary", onclick: async () => { try { const payload = { name: name.value, category: category.value, goal: goal.value, description: description.value, rules: JSON.parse(rules.value || "[]") }; if (template) await api.patch("/templates/" + template.id, payload); else await api.post("/templates", payload); document.getElementById("overlay").replaceChildren(); redraw(); } catch (error) { toast(error.message, "error"); } } }, "Save")] });
  }
  await draw();
}

function ctxCleanup(root, draw) {
  const stop = every(12000, () => draw().catch(() => {}), { immediate: false });
  const observer = new MutationObserver(() => {
    if (!document.body.contains(root)) { stop(); observer.disconnect(); }
  });
  observer.observe(document.body, { childList: true, subtree: true });
}
