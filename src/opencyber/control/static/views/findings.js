// Findings: filterable list plus a detail drawer with evidence, retests and lineage.

import {
  h, mount, api, badge, status, severity, table, fmt, loading, drawer, toast,
  field, textarea, input, select, emptyState, card, kv, code, confirmDialog, download, frag,
} from "../lib.js";

function highlight(text, quotes) {
  if (!quotes.length) return text;
  const lower = text.toLowerCase();
  const hits = [];
  for (const quote of quotes) {
    let at = lower.indexOf(quote.toLowerCase());
    while (at !== -1) {
      hits.push([at, at + quote.length]);
      at = lower.indexOf(quote.toLowerCase(), at + Math.max(1, quote.length));
    }
  }
  if (!hits.length) return text;
  hits.sort((a, b) => a[0] - b[0]);
  const merged = [];
  for (const hit of hits) {
    const last = merged[merged.length - 1];
    if (last && hit[0] <= last[1]) last[1] = Math.max(last[1], hit[1]);
    else merged.push([...hit]);
  }
  const parts = [];
  let cursor = 0;
  for (const [start, end] of merged) {
    if (start > cursor) parts.push(text.slice(cursor, start));
    parts.push(h("mark", { style: { background: "var(--sev-medium)", color: "#000", borderRadius: "3px", padding: "0 2px" } }, text.slice(start, end)));
    cursor = end;
  }
  parts.push(text.slice(cursor));
  return frag(...parts);
}

export async function renderFindings(root, ctx) {
  const state = {
    severity: ctx.params.get("severity") || "",
    triage: ctx.params.get("triage") || "",
    verification: ctx.params.get("verification") || "",
    search: ctx.params.get("search") || "",
    task_id: ctx.params.get("task_id") || "",
    sets: {},
    selected: new Set(),
  };
  const body = h("div", { class: "stack" });
  mount(
    root,
    h(
      "div",
      { class: "page-head" },
      h("div", {}, h("h1", {}, "Findings"), h("p", {}, "Every claim carries its evidence: captured exchanges, verbatim quotes and retest verdicts.")),
      h(
        "div",
        { class: "actions" },
        h("button", { class: "btn", onclick: () => exportFindings("json") }, "Export JSON"),
        h("button", { class: "btn", onclick: () => exportFindings("csv") }, "Export CSV"),
        h("button", { class: "btn", onclick: () => exportFindings("markdown") }, "Export Markdown"),
        h("button", { class: "btn", onclick: () => exportFindings("zip") }, "Evidence zip"),
        h("button", { class: "btn primary", onclick: () => createFinding(ctx) }, "New finding"),
      ),
    ),
    body,
  );

  const filters = h(
    "div",
    { class: "row wrap", style: { gap: "8px" } },
    h("div", { class: "search", style: { width: "240px" } }, h("input", { class: "input", placeholder: "Search title or summary", value: state.search, oninput: (event) => { state.search = event.target.value; draw(); } })),
    select([["", "All severities"], ["critical", "Critical"], ["high", "High"], ["medium", "Medium"], ["low", "Low"], ["info", "Info"]], { value: state.severity, style: { width: "150px" }, onchange: (event) => { state.severity = event.target.value; draw(); } }),
    select([["", "Any triage"], ["pending", "Pending"], ["in_progress", "In progress"], ["confirmed", "Confirmed"], ["resolved", "Resolved"], ["fixed", "Fixed"], ["false_positive", "False positive"], ["ignored", "Ignored"], ["duplicate", "Duplicate"], ["risk_accepted", "Risk accepted"]], { value: state.triage, style: { width: "140px" }, onchange: (event) => { state.triage = event.target.value; draw(); } }),
    select([["", "Any verification"], ["unverified", "Unverified"], ["verified", "Verified"], ["blocked", "Blocked"], ["not_assessed", "Not assessed"], ["false_positive", "False positive"]], { value: state.verification, style: { width: "160px" }, onchange: (event) => { state.verification = event.target.value; draw(); } }),
    h("div", { class: "spacer" }),
    h("button", { class: "btn sm", onclick: () => bulk("triage", "resolved") }, "Resolve selected"),
    h("button", { class: "btn sm ghost danger", onclick: () => bulk("severity", "info") }, "Downgrade selected"),
  );

  async function bulk(field_, value) {
    if (!state.selected.size) return toast("Select findings first", "error");
    try {
      await api.post("/findings/bulk", { finding_ids: [...state.selected], field: field_, value });
      toast("Updated " + state.selected.size);
      state.selected.clear();
      draw();
    } catch (error) {
      toast(error.message, "error");
    }
  }

  async function exportFindings(format) {
    const ids = state.selected.size ? [...state.selected].join(",") : "";
    const response = await api.download("/findings/export", { format, ids, task_id: state.task_id });
    const blob = await response.blob();
    const name = `findings-${new Date().toISOString().slice(0, 10)}.${format === "markdown" ? "md" : format}`;
    download(blob, name);
  }

  async function draw() {
    let payload;
    try {
      payload = await api.get("/findings", { severity: state.severity, triage: state.triage, verification: state.verification, search: state.search, task_id: state.task_id });
    } catch (error) {
      mount(body, h("div", { class: "alert danger" }, error.message));
      return;
    }
    const rows = payload.findings || [];
    mount(
      body,
      h("div", { class: "card" }, h("div", { class: "card-head" }, h("div", { class: "row" }, h("h2", {}, "Findings"), h("span", { class: "badge" }, rows.length)), filters),
        table(
          [
            {
              label: "",
              render: (row) => h("input", { type: "checkbox", checked: state.selected.has(row.id), onclick: (event) => { event.stopPropagation(); event.target.checked ? state.selected.add(row.id) : state.selected.delete(row.id); } }),
            },
            { label: "Finding", render: (row) => h("div", {}, h("a", { style: { fontWeight: 500, cursor: "pointer" }, onclick: () => open(row) }, row.title), h("div", { class: "faint", style: { fontSize: "11px" } }, (row.summary || "").slice(0, 110))) },
            { label: "Severity", render: (row) => severity(row.severity) },
            { label: "Triage", render: (row) => badge(row.triage) },
            { label: "Verification", render: (row) => badge(row.verification, row.verification === "verified" ? "ok" : "") },
            { label: "Task", render: (row) => (row.task_id ? h("a", { class: "mono", href: "#/tasks/" + row.task_id }, row.task_id.slice(0, 10)) : "—") },
            { label: "When", render: (row) => h("span", { class: "muted" }, fmt.ago(row.created)) },
          ],
          rows,
          { empty: "No findings match these filters.", action: h("button", { class: "btn", onclick: () => createFinding(ctx) }, "New finding") },
        ),
      ),
    );
  }

  async function open(finding) {
    const detail = await api.get("/findings/" + finding.id);
    const proof = await Promise.all((detail.traffic || []).map(async (item) => {
      try {
        return { item, exchange: await api.get("/traffic/" + item.exchange_id) };
      } catch {
        return { item, exchange: null };
      }
    }));
    const quotes = String(finding.evidence || "").split("\n").map((line) => line.trim()).filter(Boolean);
    const note = textarea({ placeholder: "Reviewer note" });
    const triage = select([["pending", "Pending"], ["in_progress", "In progress"], ["confirmed", "Confirmed"], ["resolved", "Resolved"], ["fixed", "Fixed"], ["false_positive", "False positive"], ["ignored", "Ignored"], ["duplicate", "Duplicate"], ["risk_accepted", "Risk accepted"]], { value: finding.triage, onchange: async (event) => { await api.patch("/findings/" + finding.id, { triage: event.target.value }); toast("Triage set"); draw(); } });
    const severitySelect = select([["critical", "Critical"], ["high", "High"], ["medium", "Medium"], ["low", "Low"], ["info", "Info"]], { value: finding.severity, onchange: async (event) => { await api.patch("/findings/" + finding.id, { severity: event.target.value }); toast("Severity set"); draw(); } });

    drawer({
      title: finding.title,
      subtitle: finding.vulnerability || finding.task_id,
      body: h(
        "div",
        { class: "stack" },
        h("div", { class: "row wrap" }, severity(finding.severity), badge(finding.triage), badge(finding.verification, finding.verification === "verified" ? "ok" : ""), ...(finding.asset_ids || []).map((id) => badge(id.slice(0, 10), "info"))),
        h("div", { style: { whiteSpace: "pre-wrap" } }, finding.summary || "No summary."),
        finding.detail ? code(finding.detail) : null,
        h("div", { class: "grid cols-2" }, field("Triage", triage), field("Severity", severitySelect)),
        h("h3", {}, "Bound traffic"),
        (detail.traffic || []).length
          ? table(
            [
              { label: "Exchange", render: (row) => h("span", { class: "mono" }, String(row.exchange_id).slice(0, 14)) },
              { label: "Role", render: (row) => badge(row.role) },
              { label: "Note", render: (row) => row.note || "—" },
              { label: "", class: "actions-cell", render: (row) => h("button", { class: "btn sm ghost danger", onclick: async () => { await api.del("/findings/" + finding.id + "/traffic", { exchange_id: row.exchange_id }); toast("Unbound"); location.reload(); } }, "Unbind") },
            ],
            detail.traffic,
          )
          : h("div", { class: "faint" }, "Nothing bound. Bind an exchange from the traffic view to keep proof."),
        proof.length
          ? h("div", { class: "stack" }, h("h3", {}, "Verbatim proof"), proof.map(({ item, exchange }) => {
              const body = String((exchange?.response_body || {}).text || "");
              return h("div", {}, h("div", { class: "faint", style: { fontSize: "11px", marginBottom: "4px" } }, `${item.role} · ${String(item.exchange_id).slice(0, 14)}`), h("pre", { class: "code", style: { maxHeight: "14rem" } }, highlight(body, quotes)));
            }))
          : null,
        h("h3", {}, "Retests"),
        (detail.retest_records || []).length
          ? table(
            [
              { label: "State", render: (row) => status(row.state) },
              { label: "Verdict", render: (row) => badge(row.verdict, row.verdict === "still_reproducible" ? "danger" : row.verdict === "fixed" ? "ok" : "warn") },
              { label: "Summary", render: (row) => row.summary || "—" },
              { label: "When", render: (row) => fmt.ago(row.created) },
              { label: "", class: "actions-cell", render: (row) => row.state === "running" || row.state === "queued" ? h("button", { class: "btn sm", onclick: async () => { await api.post("/retests/" + row.id, { verdict: "cannot_confirm", summary: "Closed by operator" }); location.reload(); } }, "Close") : null },
            ],
            detail.retest_records,
          )
          : h("div", { class: "faint" }, "Never retested."),
        (detail.retest_records || []).length
          ? h("div", { class: "stack" }, h("h3", {}, "Retest diff"), code([
              "ORIGINAL: " + (finding.summary || "—"),
              "RETEST:   " + (detail.retest_records[0].summary || "—"),
              "EVIDENCE: " + (detail.retest_records[0].evidence || "—"),
            ].join("\n")))
          : null,
        h("h3", {}, "Lineage"),
        detail.lineage?.upstream?.length || detail.lineage?.downstream?.length
          ? h("div", { class: "chip-list" }, [
            ...(detail.lineage.upstream || []).map((edge) => h("span", { class: "chip" }, "up · " + edge.kind + " · " + (edge.node?.kind || "?"))),
            ...(detail.lineage.downstream || []).map((edge) => h("span", { class: "chip" }, "down · " + edge.kind + " · " + (edge.node?.kind || "?"))),
          ])
          : h("div", { class: "faint" }, "No lineage edges."),
        field("Note", note),
      ),
      footer: [
        h("button", { class: "btn", onclick: async () => { try { const result = await api.post("/findings/" + finding.id + "/verify", { note: note.value }); toast(result.verification === "verified" ? "Quotes matched stored evidence" : "Verification: " + result.verification, result.verification === "verified" ? "ok" : "error"); } catch (error) { toast(error.message, "error"); } } }, "Verify"),
        h("button", { class: "btn", onclick: async () => { try { await api.post("/findings/" + finding.id + "/retest", { note: note.value }); toast("Retest queued"); } catch (error) { toast(error.message, "error"); } } }, "Retest"),
        h("button", { class: "btn", onclick: async () => { try { await api.post("/findings/" + finding.id + "/deepen", { instruction: note.value || "Prove the impact one step further." }); toast("Deepen intent created"); } catch (error) { toast(error.message, "error"); } } }, "Deepen"),
        h("button", { class: "btn danger", onclick: async () => { if (await confirmDialog("Delete this finding?", { danger: true, confirmLabel: "Delete" })) { await api.del("/findings/" + finding.id); toast("Deleted"); location.reload(); } } }, "Delete"),
      ],
    });
  }

  await draw();
  if (ctx.params.get("id")) {
    try {
      const finding = await api.get("/findings/" + ctx.params.get("id"));
      open(finding);
    } catch {
      /* the list is enough */
    }
  }
}

async function createFinding(ctx) {
  const title = input({ placeholder: "Exposed admin console" });
  const severityInput = select([["critical", "Critical"], ["high", "High"], ["medium", "Medium"], ["low", "Low"], ["info", "Info"]], { value: "medium" });
  const taskId = input({ placeholder: "task id (optional)" });
  const vulnerability = input({ placeholder: "exposed_admin_panel" });
  const summary = textarea({ placeholder: "What was observed and why it matters." });
  const detail = textarea({ placeholder: "Reproduction steps, request/response excerpts, impact." });
  const evidence = textarea({ placeholder: "Verbatim quotes from the captured response, one per line." });
  const assetIds = input({ placeholder: "asset ids, comma separated" });
  const { drawer: drawerFn, toast: toastFn } = await import("../lib.js");
  drawerFn({
    title: "New finding",
    body: h("div", { class: "stack" },
      field("Title", title),
      h("div", { class: "grid cols-2" }, field("Severity", severityInput), field("Task", taskId)),
      field("Vulnerability class", vulnerability),
      field("Summary", summary),
      field("Detail", detail),
      field("Evidence quotes", evidence, "Verification checks each quote against the stored response body."),
      field("Assets", assetIds),
    ),
    footer: [
      h("button", { class: "btn", onclick: () => document.getElementById("overlay").replaceChildren() }, "Cancel"),
      h("button", { class: "btn primary", onclick: async () => {
        try {
          await api.post("/findings", {
            title: title.value,
            severity: severityInput.value,
            task_id: taskId.value,
            vulnerability: vulnerability.value,
            summary: summary.value,
            detail: detail.value,
            evidence: evidence.value,
            asset_ids: assetIds.value.split(",").map((item) => item.trim()).filter(Boolean),
          });
          toastFn("Finding created");
          document.getElementById("overlay").replaceChildren();
          location.reload();
        } catch (error) {
          toastFn(error.message, "error");
        }
      } }, "Create"),
    ],
  });
}
