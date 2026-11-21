// Task detail: controls, sessions, graph, coverage, findings, assets, report.

import {
  h, mount, api, badge, status, severity, table, fmt, loading, every, navigate,
  drawer, toast, confirmDialog, field, input, textarea, select, emptyState, card,
  kv, code, progress, promptDialog, download,
} from "../lib.js";
import { graphCanvas, graphLegendCounts, coverageBars, assetTree } from "../graph.js";

const TABS = [
  ["overview", "Overview"],
  ["sessions", "Sessions"],
  ["graph", "Graph"],
  ["coverage", "Coverage"],
  ["findings", "Findings"],
  ["assets", "Assets"],
  ["intents", "Intents"],
  ["broadcast", "Broadcast"],
  ["traffic", "Traffic"],
  ["creds", "Credentials"],
  ["goals", "Goals"],
  ["report", "Report"],
];

export async function renderTask(root, ctx) {
  const taskId = ctx.task;
  let active = ctx.params.get("tab") || "overview";
  const view = h("div", { class: "stack" });
  loading(root);

  async function load() {
    const task = await api.get("/tasks/" + taskId);
    return task;
  }

  async function draw() {
    let task;
    try {
      task = await load();
    } catch (error) {
      mount(root, h("div", { class: "alert danger" }, error.message));
      return;
    }
    const header = h(
      "div",
      { class: "page-head" },
      h(
        "div",
        {},
        h("div", { class: "row" }, h("h1", {}, task.name || task.goal || taskId), status(task.status), task.category ? badge(task.category) : null),
        h("p", {}, task.goal || "no goal recorded"),
        h("div", { class: "row wrap", style: { marginTop: "6px", gap: "6px" } },
          h("span", { class: "chip mono" }, task.id),
          task.created ? h("span", { class: "chip" }, "created " + fmt.ago(task.created)) : null,
          task.started_at ? h("span", { class: "chip" }, "started " + fmt.ago(task.started_at)) : null,
          task.completion_reason ? h("span", { class: "chip" }, task.completion_reason.slice(0, 60)) : null,
        ),
      ),
      h(
        "div",
        { class: "actions" },
        task.status === "running" ? h("button", { class: "btn", onclick: () => control("pause") }, "Pause")
          : task.status === "paused" || task.status === "queued" ? h("button", { class: "btn", onclick: () => control(task.status === "queued" ? "start" : "resume") }, "Resume")
            : h("button", { class: "btn", onclick: () => control("start") }, "Start"),
        h("button", { class: "btn", onclick: () => control("stop"), disabled: !["running", "paused"].includes(task.status) }, "Stop"),
        h("button", { class: "btn", onclick: () => control("step"), title: "Run one planner/worker round" }, "Step"),
        h("button", { class: "btn", onclick: () => sendHint() }, "Hint"),
        h("button", { class: "btn", onclick: () => control("archive") }, "Archive"),
        h("button", { class: "btn danger", onclick: () => removeTask() }, "Delete"),
      ),
    );

    const tabs = h(
      "div",
      { class: "tabs" },
      TABS.map(([key, label]) => {
        const counts = key === "findings" ? task.findings?.length : key === "intents" ? task.intents?.length : key === "assets" ? task.graph?.anchors?.length : null;
        return h("button", { class: "tab" + (active === key ? " active" : ""), onclick: () => { active = key; ctx.navigate("/tasks/" + taskId, { tab: key }); } }, label, counts ? h("span", { class: "badge" }, counts) : null);
      }),
    );

    const panel = h("div", { class: "card-body", style: { padding: "0" } }, h("div", { style: { padding: "14px" }, id: "tab-panel" }, h("div", { class: "skeleton", style: { height: "80px" } })));
    mount(view, header, h("div", { class: "card" }, tabs, panel));
    mount(root, view);

    const target = panel.querySelector("#tab-panel");
    const renderers = {
      overview: () => overviewTab(task, { onHint: sendHint, onStep: () => control("step") }),
      sessions: () => sessionsTab(task, taskId, ctx),
      graph: () => graphTab(task),
      coverage: () => coverageTab(task),
      findings: () => findingsTab(task, taskId, ctx),
      assets: () => assetsTab(task, taskId, ctx),
      intents: () => intentsTab(task, taskId, ctx),
      broadcast: () => broadcastTab(task, taskId),
      traffic: () => trafficTab(task, taskId),
      creds: () => credsTab(task, taskId),
      goals: () => goalsTab(task, taskId),
      report: () => reportTab(task, taskId),
    };
    try {
      const node = await (renderers[active] || renderers.overview)();
      mount(target, node);
    } catch (error) {
      mount(target, h("div", { class: "alert danger" }, error.message));
    }
  }

  async function control(action) {
    try {
      await api.post(`/tasks/${taskId}/control`, { action });
      toast("Task " + action);
      draw();
    } catch (error) {
      toast(error.message, "error");
    }
  }

  async function sendHint() {
    const text = await promptDialog({ title: "Hint", label: "Guidance injected into the graph", multiline: true, placeholder: "Check the /admin path before brute forcing." });
    if (!text) return;
    try {
      await api.post(`/tasks/${taskId}/chat`, { message: text, run: false });
      toast("Hint added");
      draw();
    } catch (error) {
      toast(error.message, "error");
    }
  }

  async function removeTask() {
    if (!(await confirmDialog("Delete this task and its graph, intents and findings? Assets and traffic stay in the engagement.", { danger: true, confirmLabel: "Delete task" }))) return;
    try {
      await api.del(`/tasks/${taskId}`, { findings: true, traffic: true });
      toast("Task deleted");
      navigate("/tasks");
    } catch (error) {
      toast(error.message, "error");
    }
  }

  await draw();
  ctx.cleanup(every(5000, () => { if (!document.querySelector(".scrim, .modal-scrim")) draw().catch(() => {}); }, { immediate: false }));
}

// --- tabs -------------------------------------------------------------------

function overviewTab(task, { onHint, onStep }) {
  const budget = task.budget || {};
  const usage = task.usage || {};
  return h(
    "div",
    { class: "stack" },
    h(
      "div",
      { class: "grid cols-5" },
      h("div", { class: "card stat" }, h("div", { class: "label" }, "Intents"), h("div", { class: "value" }, fmt.n(task.intents?.length || 0)), h("div", { class: "sub" }, `${task.open_intents || 0} open`)),
      h("div", { class: "card stat" }, h("div", { class: "label" }, "Findings"), h("div", { class: "value" }, fmt.n(task.findings?.length || 0)), h("div", { class: "sub" }, `${task.severity_counts?.critical || 0} critical`)),
      h("div", { class: "card stat" }, h("div", { class: "label" }, "Tokens"), h("div", { class: "value" }, fmt.n(usage.total_tokens)), h("div", { class: "sub" }, `${fmt.n(usage.calls)} calls`)),
      h("div", { class: "card stat" }, h("div", { class: "label" }, "Budget left"), h("div", { class: "value" }, budget.tokens_left == null ? "∞" : fmt.n(budget.tokens_left)), h("div", { class: "sub" }, budget.seconds_left == null ? "no time cap" : fmt.duration(budget.seconds_left) + " left")),
      h("div", { class: "card stat" }, h("div", { class: "label" }, "Approvals"), h("div", { class: "value" }, fmt.n(task.approvals_pending)), h("div", { class: "sub" }, "pending decisions")),
    ),
    h(
      "div",
      { class: "grid cols-2" },
      h(
        "div",
        { class: "stack" },
        h("h3", {}, "Configuration"),
        kv([
          ["Goal", task.goal || "—"],
          ["Description", task.description || "—"],
          ["Scope", (task.scope || []).length ? h("div", { class: "chip-list" }, task.scope.map((entry) => h("span", { class: "chip mono" }, entry))) : "engagement-wide"],
          ["Enforcement", h("div", { class: "row wrap" }, badge(task.scope_enforcement ? "scope on" : "scope off", task.scope_enforcement ? "ok" : "warn"), badge(task.offline ? "offline" : "online", task.offline ? "ok" : ""))],
          ["LLM profiles", (task.llm_profile_ids || []).join(", ") || "router default"],
          ["Rotate", task.llm_rotate ? "yes" : "no"],
          ["Timeout", task.timeout_minutes ? task.timeout_minutes + " min" : "none"],
          ["Require finding", task.require_finding ? "yes" : "no"],
          ["Created", fmt.clock(task.created)],
          ["Started", fmt.clock(task.started_at)],
          ["Finished", fmt.clock(task.finished_at)],
          ["Reason", task.completion_reason || "—"],
        ]),
      ),
      h(
        "div",
        { class: "stack" },
        h("h3", {}, "Activity"),
        h("div", { class: "row" }, h("button", { class: "btn sm", onclick: onStep }, "Run one round"), h("button", { class: "btn sm", onclick: onHint }, "Add hint")),
        progress(budget.tokens_total ? 1 - (budget.tokens_left || 0) / budget.tokens_total : (usage.total_tokens || 0) / Math.max(1, Number(task.budgets?.tokens) || 1), "Token budget used"),
        h("div", { class: "faint" }, "Recent intents"),
        h("div", { class: "list" }, (task.intents || []).slice(-8).reverse().map((intent) =>
          h("div", { class: "list-item" }, h("div", { class: "row", style: { justifyContent: "space-between" } }, h("span", { class: "title" }, intent.title), status(intent.status)), h("div", { class: "meta" }, intent.summary || intent.instruction || "")))),
      ),
    ),
  );
}

async function sessionsTab(task, taskId, ctx) {
  const [messages, events] = await Promise.all([
    api.get(`/tasks/${taskId}/messages`).catch(() => ({ records: [] })),
    api.get(`/tasks/${taskId}/events`).catch(() => ({ records: [] })),
  ]);
  const transcript = h("div", { class: "transcript" });
  for (const message of (messages.records || []).slice().reverse()) {
    transcript.append(h("div", { class: "bubble " + (message.role === "operator" ? "user" : "agent") }, h("div", { class: "who" }, message.role + " · " + fmt.ago(message.created)), message.content));
  }
  if (!(messages.records || []).length) transcript.append(h("div", { class: "empty-state" }, h("strong", {}, "No messages"), "Operator hints and planner notes appear here."));

  const input_ = textarea({ placeholder: "Message the planner. Use @asset or @finding to reference a node.", style: { minHeight: "54px" } });
  const composer = h(
    "div",
    { class: "chat-composer" },
    input_,
    h("button", {
      class: "btn primary",
      onclick: async () => {
        const text = input_.value.trim();
        if (!text) return;
        try {
          await api.post(`/tasks/${taskId}/chat`, { message: text });
          input_.value = "";
          ctx.navigate("/tasks/" + taskId, { tab: "sessions" });
          location.reload();
        } catch (error) {
          toast(error.message, "error");
        }
      },
    }, "Send"),
  );

  return h(
    "div",
    { class: "sessions" },
    h(
      "div",
      { class: "rail" },
      h("div", { class: "list" }, (task.intents || []).slice().reverse().map((intent) =>
        h("div", { class: "list-item" }, h("div", { class: "row", style: { justifyContent: "space-between" } }, h("span", { class: "title" }, intent.title), status(intent.status)), h("div", { class: "meta" }, fmt.ago(intent.created) + " · " + (intent.worker || "unclaimed"))))),
    ),
    h("div", { style: { display: "flex", flexDirection: "column", minHeight: 0 } }, transcript, composer),
  );
}

function graphTab(task) {
  const detail = h("div", { class: "card", style: { marginTop: "10px" } }, h("div", { class: "card-body" }, h("div", { class: "faint" }, "Select a node to inspect it.")));
  const canvas = graphCanvas(task.graph, {
    height: 520,
    onSelect: async (node) => {
      const data = await api.get(`/tasks/${task.id}/graph`);
      const edges = data.edges || [];
      const inbound = edges.filter((edge) => edge.target === node.id);
      const outbound = edges.filter((edge) => edge.source === node.id);
      mount(
        detail,
        h(
          "div",
          { class: "card-body stack" },
          h("div", { class: "row" }, badge(node.kind, node.kind === "finding" ? "danger" : node.kind === "intent" ? "info" : ""), status(node.state), h("span", { class: "mono faint" }, node.id)),
          h("div", { style: { fontWeight: 500 } }, node.summary || node.label),
          node.payload ? code(node.payload) : null,
          h("div", { class: "grid cols-2" },
            h("div", {}, h("div", { class: "faint" }, `Inbound (${inbound.length})`), h("div", { class: "list" }, inbound.map((edge) => h("div", { class: "list-item" }, h("span", { class: "meta" }, edge.kind), h("span", { class: "title mono", style: { fontSize: "11px" } }, edge.source.slice(0, 18)))))),
            h("div", {}, h("div", { class: "faint" }, `Outbound (${outbound.length})`), h("div", { class: "list" }, outbound.map((edge) => h("div", { class: "list-item" }, h("span", { class: "meta" }, edge.kind), h("span", { class: "title mono", style: { fontSize: "11px" } }, edge.target.slice(0, 18)))))),
          ),
        ),
      );
    },
  });
  return h("div", { class: "stack" }, h("div", { class: "row wrap", style: { justifyContent: "space-between" } }, graphLegendCounts(task.graph), h("div", { class: "row" }, h("a", { class: "btn sm", href: "#/findings?task_id=" + task.id }, "Findings"))), canvas, detail);
}

function coverageTab(task) {
  return h(
    "div",
    { class: "stack" },
    h("p", { class: "muted", style: { margin: 0 } }, "Coverage over the engagement's asset graph for this task."),
    coverageBars(task.coverage),
  );
}

async function findingsTab(task, taskId, ctx) {
  const rows = task.findings || [];
  const openFinding = async (finding) => {
    const detail = await api.get("/findings/" + finding.id);
    const notes = textarea({ placeholder: "Reviewer note" });
    drawer({
      title: finding.title,
      subtitle: finding.severity + " · " + finding.triage + " · " + finding.verification,
      body: h(
        "div",
        { class: "stack" },
        h("div", { class: "row" }, severity(finding.severity), badge(finding.triage), badge(finding.verification, finding.verification === "verified" ? "ok" : ""), finding.vulnerability ? badge(finding.vulnerability) : null),
        h("div", { style: { whiteSpace: "pre-wrap" } }, finding.summary || "No summary."),
        finding.detail ? h("pre", { class: "code" }, finding.detail) : null,
        h("h3", {}, "Evidence"),
        (detail.traffic || []).length ? table([{ label: "Exchange", render: (row) => h("span", { class: "mono" }, row.exchange_id?.slice(0, 16)) }, { label: "Role", render: (row) => badge(row.role) }, { label: "Note", key: "note" }], detail.traffic) : h("div", { class: "faint" }, "No traffic bound yet."),
        h("h3", {}, "Retests"),
        (detail.retest_records || []).length ? table([{ label: "State", render: (row) => status(row.state) }, { label: "Verdict", render: (row) => badge(row.verdict) }, { label: "When", render: (row) => fmt.ago(row.created) }], detail.retest_records) : h("div", { class: "faint" }, "Never retested."),
        field("Note", notes),
        h("div", { class: "row wrap" },
          h("button", { class: "btn", onclick: async () => { try { await api.post(`/findings/${finding.id}/verify`, { note: notes.value }); toast("Verified against stored evidence"); ctx.navigate("/tasks/" + taskId, { tab: "findings" }); location.reload(); } catch (error) { toast(error.message, "error"); } } }, "Verify quotes"),
          h("button", { class: "btn", onclick: async () => { try { await api.post(`/findings/${finding.id}/retest`, { note: notes.value }); toast("Retest queued"); } catch (error) { toast(error.message, "error"); } } }, "Start retest"),
          h("button", { class: "btn", onclick: async () => { try { await api.post(`/findings/${finding.id}/deepen`, { instruction: notes.value || "Go one step further and prove impact." }); toast("Deepen intent created"); } catch (error) { toast(error.message, "error"); } } }, "Deepen"),
        ),
      ),
    });
  };
  return h(
    "div",
    { class: "stack" },
    table(
      [
        { label: "Finding", render: (row) => h("a", { style: { fontWeight: 500, cursor: "pointer" }, onclick: () => openFinding(row) }, row.title) },
        { label: "Severity", render: (row) => severity(row.severity) },
        { label: "Triage", render: (row) => badge(row.triage) },
        { label: "Verification", render: (row) => badge(row.verification, row.verification === "verified" ? "ok" : "") },
        { label: "When", render: (row) => h("span", { class: "muted" }, fmt.ago(row.created)) },
      ],
      rows,
      { empty: "No findings for this task yet." },
    ),
  );
}

async function assetsTab(task, taskId, ctx) {
  const payload = await api.get(`/tasks/${taskId}/assets`);
  const rows = payload.assets || [];
  return h(
    "div",
    { class: "stack" },
    h("div", { class: "row", style: { justifyContent: "space-between" } }, h("h3", {}, `${rows.length} anchored assets`), h("button", { class: "btn sm", onclick: () => import("./assets_helper.js").then((module) => module.addAssetsDialog(taskId)) }, "+ Attach")),
    table(
      [
        { label: "Asset", render: (row) => h("span", { class: "mono" }, row.value) },
        { label: "Kind", render: (row) => badge(row.kind) },
        { label: "Source", render: (row) => (row.sources || []).join(", ") || "—" },
        { label: "", class: "actions-cell", render: (row) => h("button", { class: "btn sm ghost", onclick: async () => { await api.del(`/tasks/${taskId}/assets`, { asset_id: row.id }); toast("Detached from this task"); ctx.navigate("/tasks/" + taskId, { tab: "assets" }); location.reload(); } }, "Detach") },
      ],
      rows,
      { empty: "No assets anchored yet. Anchoring links this task's intents and findings to a shared asset." },
    ),
  );
}

function intentsTab(task, taskId, ctx) {
  return table(
    [
      { label: "Intent", render: (row) => h("div", {}, h("div", { style: { fontWeight: 500 } }, row.title), h("div", { class: "faint", style: { fontSize: "11px" } }, (row.instruction || "").slice(0, 120))) },
      { label: "Status", render: (row) => status(row.status) },
      { label: "Priority", num: true, key: "priority" },
      { label: "Worker", render: (row) => h("span", { class: "mono" }, row.worker || "—") },
      { label: "Created", render: (row) => h("span", { class: "muted" }, fmt.ago(row.created)) },
      {
        label: "",
        class: "actions-cell",
        render: (row) => ["failed", "blocked", "cancelled", "done", "budget_exhausted"].includes(row.status)
          ? h("button", { class: "btn sm", onclick: async (event) => { event.stopPropagation(); try { await api.post(`/tasks/${taskId}/intents/${row.id}`); toast("Intent requeued"); location.reload(); } catch (error) { toast(error.message, "error"); } } }, "Rerun")
          : null,
      },
    ],
    task.intents || [],
    { empty: "The planner has not dispatched any intents yet." },
  );
}

async function broadcastTab(task, taskId) {
  const [nodes, messages] = await Promise.all([
    api.get(`/tasks/${taskId}/broadcast`).catch(() => ({ records: [] })),
    api.get(`/tasks/${taskId}/messages`).catch(() => ({ records: [] })),
  ]);
  const entries = [
    ...(nodes.records || []).map((node) => ({ at: node.created, kind: node.kind, text: node.summary || node.label, state: node.state })),
    ...(messages.records || []).map((message) => ({ at: message.created, kind: "operator." + message.role, text: message.content, state: "" })),
  ].sort((a, b) => String(b.at).localeCompare(String(a.at)));
  return h(
    "div",
    { class: "stack" },
    h("p", { class: "muted", style: { margin: 0 } }, "Everything the task published to its graph, newest first."),
    h("div", { class: "list" }, entries.map((entry) =>
      h("div", { class: "list-item" }, h("div", { class: "row", style: { justifyContent: "space-between" } }, h("span", { class: "meta" }, entry.kind), h("span", { class: "faint" }, fmt.ago(entry.at))), h("div", { class: "title", style: { fontWeight: 400 } }, entry.text)))),
  );
}

async function trafficTab(task, taskId) {
  const payload = await api.get("/traffic", { limit: 100, search: "" }).catch(() => ({ records: [] }));
  const rows = (payload.records || []).filter((row) => (row.tags || []).includes(taskId));
  return h(
    "div",
    { class: "stack" },
    h("div", { class: "row", style: { justifyContent: "space-between" } }, h("h3", {}, `${rows.length} captured exchanges`), h("a", { class: "btn sm", href: "#/traffic" }, "Open traffic")),
    table(
      [
        { label: "Method", render: (row) => badge(row.method, "info") },
        { label: "URL", render: (row) => h("span", { class: "mono", style: { fontSize: "11px" } }, (row.url || "").slice(0, 90)) },
        { label: "Status", render: (row) => badge(row.status, row.status >= 400 ? "warn" : "ok") },
        { label: "When", render: (row) => h("span", { class: "muted" }, fmt.ago(row.created)) },
      ],
      rows,
      { empty: "No traffic tagged with this task." },
    ),
  );
}

async function credsTab(task, taskId) {
  const payload = await api.get(`/tasks/${taskId}/credentials`);
  const rows = payload.credentials || [];
  const domain = input({ placeholder: "app.acme.test" });
  const username = input({ placeholder: "admin" });
  const password = input({ placeholder: "leave blank to let the agent generate", type: "password" });
  return h(
    "div",
    { class: "stack" },
    h("div", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Task credentials")), h("div", { class: "card-body" },
      h("div", { class: "inline-form" },
        field("Domain", domain), field("Username", username), field("Password", password),
        h("button", { class: "btn primary", onclick: async () => { try { await api.post(`/tasks/${taskId}/credentials`, { domain: domain.value, username: username.value, password: password.value }); toast("Credential added"); location.reload(); } catch (error) { toast(error.message, "error"); } } }, "Add"),
      ),
      h("p", { class: "faint", style: { marginBottom: 0 } }, "Passwords are never returned by the API; only whether one exists and who generated it."),
    )),
    table(
      [
        { label: "Domain", render: (row) => h("span", { class: "mono" }, row.domain) },
        { label: "Username", render: (row) => h("span", { class: "mono" }, row.username) },
        { label: "Secret", render: (row) => badge(row.password_label, row.agent_generated ? "violet" : "") },
        { label: "Note", key: "note" },
        { label: "", class: "actions-cell", render: (row) => h("button", { class: "btn sm ghost danger", onclick: async () => { await api.del(`/tasks/${taskId}/credentials/${row.id}`); location.reload(); } }, "Delete") },
      ],
      rows,
      { empty: "No credentials stored for this task." },
    ),
  );
}

async function goalsTab(task, taskId) {
  const payload = await api.get(`/tasks/${taskId}/goals`);
  const rows = payload.goals || [];
  const text = input({ placeholder: "Prove authenticated access to the admin panel" });
  return h(
    "div",
    { class: "stack" },
    h("div", { class: "inline-form" }, field("New goal", text), h("button", { class: "btn primary", onclick: async () => { try { await api.post(`/tasks/${taskId}/goals`, { text: text.value }); location.reload(); } catch (error) { toast(error.message, "error"); } } }, "Add")),
    table(
      [
        { label: "Goal", render: (row) => row.text },
        { label: "Class", render: (row) => row.vulnerability_class ? badge(row.vulnerability_class) : "—" },
        { label: "State", render: (row) => status(row.state) },
        { label: "", class: "actions-cell", render: (row) => h("button", { class: "btn sm ghost danger", onclick: async () => { await api.del(`/tasks/${taskId}/goals/${row.id}`); location.reload(); } }, "Delete") },
      ],
      rows,
      { empty: "No explicit goals. The task goal is used." },
    ),
  );
}

async function reportTab(task, taskId) {
  const payload = await api.get(`/tasks/${taskId}/report`);
  const pre = h("pre", { class: "code", style: { maxHeight: "none" } }, payload.markdown || "No report yet.");
  return h(
    "div",
    { class: "stack" },
    h("div", { class: "row" },
      h("button", { class: "btn", onclick: async () => { const response = await api.download("/findings/export", { format: "markdown", ids: (task.findings || []).map((item) => item.id).join(",") }); download(await response.blob(), task.id + "-findings.md"); } }, "Export findings (markdown)"),
      h("button", { class: "btn", onclick: async () => { const response = await api.download("/findings/export", { format: "csv", ids: (task.findings || []).map((item) => item.id).join(",") }); download(await response.blob(), task.id + "-findings.csv"); } }, "Export findings (csv)"),
      h("button", { class: "btn primary", onclick: async () => { const response = await api.download("/findings/export", { format: "zip", ids: (task.findings || []).map((item) => item.id).join(",") }); download(await response.blob(), task.id + "-evidence-bundle.zip"); } }, "Evidence bundle (zip)"),
    ),
    pre,
  );
}
