// Traffic: captured exchanges, request detail, replay, HAR import/export.

import {
  h, mount, api, badge, status, table, fmt, loading, drawer, toast, field, input,
  select, textarea, emptyState, card, code, confirmDialog, download,
} from "../lib.js";

export async function renderTraffic(root, ctx) {
  const state = {
    host: ctx.params.get("host") || "",
    method: ctx.params.get("method") || "",
    status_class: ctx.params.get("status_class") || "",
    search: ctx.params.get("search") || "",
    body: "",
    limit: 60,
    offset: 0,
    payload: { records: [], total: 0, hosts: [] },
    capture: null,
    selected: null,
  };

  const list = h("div", { class: "stack" });
  const detailPane = h("div", { class: "pane-right" }, h("div", { class: "empty-state" }, h("strong", {}, "Select an exchange"), "Request and response bodies, headers, replay and evidence binding."));

  mount(
    root,
    h(
      "div",
      { class: "page-head" },
      h("div", {}, h("h1", {}, "Traffic"), h("p", {}, "Captured and replayed HTTP. Every replay passes the same scope, blocklist and noise governor as the agents.")),
      h(
        "div",
        { class: "actions" },
        h("button", { class: "btn", onclick: () => importHAR() }, "Import HAR"),
        h("button", { class: "btn", onclick: () => exportHAR() }, "Export HAR"),
        h("button", { class: "btn danger", onclick: () => purge() }, "Purge"),
      ),
    ),
    h("div", { class: "card", style: { marginBottom: "12px" } }, h("div", { class: "card-body" },
      h(
        "div",
        { class: "row wrap", style: { gap: "8px" } },
        h("div", { class: "search", style: { width: "230px" } }, h("input", { class: "input", placeholder: "Search url, status, type", value: state.search, oninput: (event) => { state.search = event.target.value; reload(); } })),
        select([["", "All methods"], ["GET", "GET"], ["POST", "POST"], ["PUT", "PUT"], ["PATCH", "PATCH"], ["DELETE", "DELETE"]], { value: state.method, style: { width: "130px" }, onchange: (event) => { state.method = event.target.value; reload(); } }),
        select([["", "Any status"], ["2xx", "2xx"], ["3xx", "3xx"], ["4xx", "4xx"], ["5xx", "5xx"]], { value: state.status_class, style: { width: "130px" }, onchange: (event) => { state.status_class = event.target.value; reload(); } }),
        h("div", { class: "search", style: { width: "200px" } }, h("input", { class: "input", placeholder: "Body contains", oninput: (event) => { state.body = event.target.value; reload(); } })),
        hostSelect(),
        h("div", { class: "spacer" }),
        h("label", { class: "check" }, h("input", { type: "checkbox", checked: !!state.capture, onchange: async (event) => { await api.put("/settings", { traffic_capture: event.target.checked }); state.capture = event.target.checked; toast(event.target.checked ? "Capture on" : "Capture off"); } }), "Capture"),
      ),
    )),
    h("div", { class: "split wide" }, h("div", { class: "card" }, h("div", { class: "card-head" }, h("div", { class: "row" }, h("h2", {}, "Exchanges"), h("span", { class: "badge", id: "traffic-total" }, "0"))), list), detailPane),
  );

  function hostSelect() {
    const node = select([["", "All hosts"], ...(state.payload.hosts || []).map((entry) => [entry.host, `${entry.host} (${entry.count})`])], { value: state.host, style: { width: "190px" }, onchange: (event) => { state.host = event.target.value; reload(); } });
    return node;
  }

  async function reload() {
    try {
      state.payload = await api.get("/traffic", {
        host: state.host,
        method: state.method,
        status_class: state.status_class,
        search: state.search,
        body: state.body,
        limit: state.limit,
        offset: state.offset,
      });
    } catch (error) {
      mount(list, h("div", { class: "alert danger" }, error.message));
      return;
    }
    const rows = state.payload.records || [];
    const total = document.getElementById("traffic-total");
    if (total) total.textContent = fmt.n(state.payload.total);
    mount(
      list,
      rows.length
        ? h("div", { class: "list" }, rows.map((row) =>
          h(
            "div",
            { class: "list-item" + (state.selected?.id === row.id ? " active" : ""), dataset: { id: row.id }, onclick: () => select(row) },
            h("div", { class: "row", style: { justifyContent: "space-between" } },
              h("span", { class: "row", style: { gap: "5px" } }, badge(row.method, "info"), h("span", { class: "mono", style: { fontSize: "11px" } }, (row.url || "").replace(/^https?:\/\//, "").slice(0, 46))),
              badge(row.status, row.status >= 500 ? "danger" : row.status >= 400 ? "warn" : "ok"),
            ),
            h("div", { class: "meta" }, `${fmt.ago(row.created)} · ${fmt.bytes(row.response_body?.bytes || 0)} · ${(row.content_type || "").split(";")[0] || "unknown"}`),
          ),
        ))
        : emptyState("No exchanges", "Traffic appears when a tool makes a request with capture on, or when you import a HAR.", h("button", { class: "btn", onclick: () => importHAR() }, "Import HAR")),
    );
    if (!rows.length) {
      state.selected = null;
      mount(detailPane, h("div", { class: "empty-state" }, h("strong", {}, "No exchange selected"), "Import a HAR or capture traffic to inspect a request."));
      return;
    }
    if (rows.length && !state.selected) select(rows[0]);
    else if (state.selected && rows.some((row) => row.id === state.selected.id)) select(state.selected);
  }

  function select(row) {
    if (!row || !row.id) return;
    state.selected = row;
    for (const item of list.querySelectorAll(".list-item")) item.classList.toggle("active", item.dataset.id === row.id);
    const requestBody = row.request_body || {};
    const responseBody = row.response_body || {};
    const replayResult = h("div");
    const findingId = input({ placeholder: "finding id" });
    mount(
      detailPane,
      h(
        "div",
        { class: "stack" },
        h("div", { class: "row wrap" }, badge(row.method, "info"), h("span", { class: "mono", style: { fontSize: "11.5px" } }, row.url), badge(row.status, row.status >= 400 ? "warn" : "ok")),
        h("div", { class: "row wrap" }, h("span", { class: "chip" }, "source " + (row.source || "capture")), row.replayed_from ? h("span", { class: "chip" }, "replay of " + row.replayed_from.slice(0, 10)) : null, h("span", { class: "chip" }, fmt.clock(row.created)), h("span", { class: "chip" }, fmt.bytes((requestBody.bytes || 0) + (responseBody.bytes || 0)))),
        h("div", { class: "tabs" }, h("button", { class: "tab active" }, "Request"), h("button", { class: "tab" }, "Response"), h("button", { class: "tab" }, "Evidence")),
        h("h3", {}, "Request"),
        code(`${row.method} ${row.url}\n` + Object.entries(row.request_headers || {}).map(([key, value]) => `${key}: ${value}`).join("\n") + "\n\n" + (requestBody.text || "")),
        h("h3", {}, "Response"),
        code(`HTTP ${row.status}\n` + Object.entries(row.response_headers || {}).map(([key, value]) => `${key}: ${value}`).join("\n") + "\n\n" + (responseBody.text || "")),
        h("div", { class: "row wrap" },
          h("button", { class: "btn", onclick: async (event) => { event.target.disabled = true; try { const result = await api.post("/traffic/replay", { exchange_id: row.id }); toast("Replayed · " + result.status + " in " + (result.governor?.waited_ms || 0) + "ms wait"); mount(replayResult, h("div", { class: "alert info" }, `Replay ${result.status} · ${fmt.bytes((result.body || "").length)} · ${result.truncated ? "truncated" : "complete"}`)); reload(); } catch (error) { toast(error.message, "error"); } finally { event.target.disabled = false; } } }, "Replay"),
          h("button", { class: "btn", onclick: () => import("./assets_helper.js").then((module) => module.bindTrafficDialog(row.id)) }, "Bind to finding"),
          h("button", { class: "btn", onclick: () => { const body = textarea({ value: requestBody.text || "", style: { minHeight: "120px" } }); const method = select(["GET", "POST", "PUT", "PATCH", "DELETE"], { value: row.method }); drawer({ title: "Edit and replay", body: h("div", { class: "stack" }, h("div", { class: "grid cols-2" }, field("Method", method), field("URL", input({ value: row.url }))), field("Body", body)), footer: [h("button", { class: "btn primary", onclick: async () => { try { const result = await api.post(`/traffic/${row.id}/replay`, { method: method.value, body: body.value }); toast("Replayed · " + result.status); } catch (error) { toast(error.message, "error"); } } }, "Send")] }); } }, "Edit & replay"),
          h("button", { class: "btn ghost danger", onclick: async () => { if (await confirmDialog("Delete this exchange?", { danger: true, confirmLabel: "Delete" })) { await api.del("/traffic/" + row.id); toast("Deleted"); state.selected = null; reload(); } } }, "Delete"),
        ),
        replayResult,
        h("h3", {}, "Evidence"),
        h("div", { class: "inline-form" }, field("Finding", findingId), h("button", { class: "btn", onclick: async () => { try { await api.post("/findings/" + findingId.value + "/traffic", { exchange_ids: [row.id], role: "supporting" }); toast("Bound as supporting evidence"); } catch (error) { toast(error.message, "error"); } } }, "Bind")),
      ),
    );
  }

  async function importHAR() {
    const textareaNode = textarea({ placeholder: "Paste a HAR document", style: { minHeight: "180px" } });
    drawer({
      title: "Import HAR",
      body: h("div", { class: "stack" }, field("HAR", textareaNode, "Entries outside the engagement scope are rejected, not silently dropped."), h("div", { class: "faint" }, "You can also choose a file."), h("input", { type: "file", accept: ".har,.json", onchange: async (event) => { const file = event.target.files?.[0]; if (file) textareaNode.value = await file.text(); } })),
      footer: [h("button", { class: "btn primary", onclick: async () => {
        try {
          const document_ = JSON.parse(textareaNode.value);
          const result = await api.post("/traffic/har", document_);
          toast(`Imported ${result.imported} of ${result.total} entries`);
          document.getElementById("overlay").replaceChildren();
          reload();
        } catch (error) {
          toast(error.message, "error");
        }
      } }, "Import")],
    });
  }

  async function exportHAR() {
    const response = await api.download("/traffic/har");
    download(await response.blob(), "traffic.har");
  }

  async function purge() {
    const host = await (await import("../lib.js")).promptDialog({ title: "Purge traffic", label: "Host (blank purges every exchange)", placeholder: "app.acme.test" });
    if (host === null) return;
    if (!(await confirmDialog(`Delete ${host || "all"} captured traffic?`, { danger: true, confirmLabel: "Purge" }))) return;
    try {
      const result = await api.post("/traffic/purge", { host });
      toast(`Purged ${result.deleted} exchanges`);
      state.selected = null;
      reload();
    } catch (error) {
      toast(error.message, "error");
    }
  }

  await api.get("/settings").then((payload) => { state.capture = payload.capture; }).catch(() => {});
  await reload();
}
