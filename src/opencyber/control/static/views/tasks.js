// Tasks: the run list, the category rail, and the create flow.

import {
  h, mount, api, badge, status, severity, table, fmt, loading, every, navigate,
  drawer, toast, confirmDialog, field, input, textarea, select, emptyState, card, promptDialog,
} from "../lib.js";

export async function renderTasks(root, ctx) {
  const state = {
    status: ctx.params.get("status") || "",
    category: ctx.params.get("category") || "",
    search: ctx.params.get("search") || "",
    archive: ctx.params.get("archive") === "1",
    rows: [],
    categories: [],
  };

  const body = h("div", { class: "stack" });
  mount(
    root,
    h(
      "div",
      { class: "page-head" },
      h("div", {}, h("h1", {}, "Tasks"), h("p", {}, "Each task is one engagement-scoped autonomous run with its own budget, graph and findings.")),
      h("div", { class: "actions" }, h("a", { class: "btn", href: "#/templates" }, "Templates"), h("button", { class: "btn primary", onclick: () => openCreate(ctx) }, "New task")),
    ),
    body,
  );

  const filters = h(
    "div",
    { class: "row wrap", style: { gap: "8px" } },
    h("div", { class: "search", style: { width: "260px" } }, h("input", { class: "input", placeholder: "Search name, goal or id", value: state.search, oninput: (event) => { state.search = event.target.value; draw(); } })),
    select([["", "All statuses"], ["running", "Running"], ["queued", "Queued"], ["paused", "Paused"], ["completed", "Completed"], ["failed", "Failed"], ["stopped", "Stopped"], ["archived", "Archived"]], { value: state.status, style: { width: "150px" }, onchange: (event) => { state.status = event.target.value; draw(); } }),
    h("div", { class: "spacer" }),
    h("button", { class: "btn sm", onclick: () => { state.archive = !state.archive; draw(); } }, state.archive ? "Show active" : "Show archive"),
  );

  async function load() {
    const [tasks, categories] = await Promise.all([
      api.get("/tasks", { status: state.archive ? "archived" : state.status, category: state.archive ? "" : state.category, search: state.search, limit: 200 }),
      api.get("/categories").catch(() => ({ categories: [] })),
    ]);
    state.rows = (tasks.records || []).filter((row) => (state.archive ? row.status === "archived" || row.archived_at : true));
    state.categories = categories.categories || [];
  }

  async function draw() {
    try {
      await load();
    } catch (error) {
      mount(body, h("div", { class: "alert danger" }, error.message));
      return;
    }
    const layout = h(
      "div",
      { class: "split" },
      h(
        "div",
        { class: "card", style: { position: "sticky", top: "64px" } },
        h("div", { class: "card-head" }, h("h2", {}, "Categories"), h("button", { class: "btn sm ghost", onclick: () => addCategory(ctx, state, draw) }, "+")),
        h(
          "div",
          { class: "list" },
          h("div", { class: "list-item" + (state.category === "" ? " active" : ""), onclick: () => { state.category = ""; draw(); }, style: { display: "flex" } }, h("span", { class: "title" }, "All tasks"), h("span", { class: "meta", style: { marginLeft: "auto" } }, state.rows.length)),
          state.categories.map((category) =>
            h(
              "div",
              { class: "list-item" + (state.category === category.name ? " active" : "") },
              h("div", { class: "row", style: { justifyContent: "space-between" } },
                h("span", { class: "title", onclick: () => { state.category = category.name; draw(); } }, category.name),
                h("span", { class: "meta" }, category.task_count ?? 0),
              ),
              h("div", { class: "row", style: { gap: "4px", marginTop: "2px" } },
                h("button", { class: "btn sm ghost", onclick: async (event) => { event.stopPropagation(); const next = await promptDialog({ title: "Rename category", label: "Name", value: category.name }); if (next) { await api.patch("/categories/" + encodeURIComponent(category.name), { name: next }); draw(); } } }, "Rename"),
                h("button", { class: "btn sm ghost danger", onclick: async (event) => { event.stopPropagation(); if (await confirmDialog(`Delete ${category.name}? Its tasks move to uncategorized.`, { danger: true, confirmLabel: "Delete" })) { await api.del("/categories/" + encodeURIComponent(category.name)); draw(); } } }, "Delete"),
              ),
            ),
          ),
        ),
      ),
      h(
        "div",
        { class: "card" },
        h("div", { class: "card-head" }, h("div", { class: "row" }, h("h2", {}, "Runs"), h("span", { class: "badge" }, state.rows.length)), filters),
        table(
          [
            { label: "Task", render: (row) => h("div", {}, h("a", { href: "#/tasks/" + row.id, style: { fontWeight: 500 } }, row.name || row.goal || row.id), h("div", { class: "faint", style: { fontSize: "11px" } }, (row.goal || "").slice(0, 100))) },
            { label: "Status", render: (row) => h("div", { class: "row", style: { gap: "4px" } }, status(row.status), row.category ? badge(row.category) : null) },
            {
              label: "Findings",
              num: true,
              render: (row) => {
                const counts = row.severity_counts || {};
                const total = row.findings || 0;
                return total ? h("div", { class: "row", style: { justifyContent: "flex-end", gap: "3px" } }, ["critical", "high", "medium", "low"].filter((name) => counts[name]).map((name) => h("span", { class: "badge sev-" + name }, counts[name]))) : h("span", { class: "faint" }, "0");
              },
            },
            { label: "Intents", num: true, render: (row) => h("span", { class: "mono" }, `${row.open_intents || 0}/${row.total_intents || 0}`) },
            { label: "Tokens", num: true, render: (row) => h("span", { class: "mono" }, fmt.n(row.tokens?.total)) },
            { label: "Budget", num: true, render: (row) => h("span", { class: "mono" }, row.budget?.tokens_left != null ? fmt.n(row.budget.tokens_left) : "∞") },
            { label: "Duration", num: true, render: (row) => h("span", { class: "muted" }, fmt.duration(row.duration_seconds)) },
            {
              label: "",
              class: "actions-cell",
              render: (row) => h(
                "div",
                { class: "row", style: { gap: "4px", justifyContent: "flex-end" } },
                row.status === "running" ? h("button", { class: "btn sm", onclick: (event) => { event.stopPropagation(); control(row.id, "pause"); } }, "Pause")
                  : row.status === "paused" || row.status === "queued" ? h("button", { class: "btn sm", onclick: (event) => { event.stopPropagation(); control(row.id, row.status === "queued" ? "start" : "resume"); } }, "Resume")
                    : row.status === "archived" ? h("button", { class: "btn sm", onclick: (event) => { event.stopPropagation(); control(row.id, "restore"); } }, "Restore")
                      : h("button", { class: "btn sm", onclick: (event) => { event.stopPropagation(); control(row.id, "start"); } }, "Start"),
                h("a", { class: "btn sm ghost", href: "#/tasks/" + row.id }, "Open"),
              ),
            },
          ],
          state.rows,
          { empty: "No tasks match this filter." },
        ),
      ),
    );
    mount(body, layout);
  }

  async function control(taskId, action) {
    try {
      await api.post(`/tasks/${taskId}/control`, { action });
      toast(`Task ${action}`);
      draw();
      ctx.refreshShell?.();
    } catch (error) {
      toast(error.message, "error");
    }
  }

  await draw();
  ctx.cleanup(every(6000, () => draw().catch(() => {}), { immediate: false }));
  if (ctx.params.get("create")) openCreate(ctx);
}

async function addCategory(ctx, state, redraw) {
  const name = await promptDialog({ title: "New category", label: "Name", placeholder: "External web" });
  if (!name) return;
  try {
    await api.post("/categories", { name });
    redraw();
  } catch (error) {
    toast(error.message, "error");
  }
}

export async function openCreate(ctx) {
  let profiles = [];
  try {
    const payload = await api.get("/llm/profiles");
    profiles = payload.profiles || [];
  } catch {
    profiles = [];
  }
  let templates = [];
  try {
    templates = (await api.get("/templates")).templates || [];
  } catch {
    templates = [];
  }
  const values = {
    name: "",
    goal: "",
    description: "",
    category: "",
    scope: "",
    budgets: { tokens: "", seconds: "", dollars: "" },
    profile: profiles.find((item) => item.active)?.id || profiles[0]?.id || "",
    rotate: false,
    timeout_minutes: "",
    require_finding: false,
    template_id: "",
    rules: [],
    start: true,
  };

  const form = h("div", { class: "stack" });
  const body = h(
    "div",
    { class: "stack" },
    templates.length
      ? field(
        "Template",
        select([["", "None"], ...templates.map((item) => [item.id, item.name])], {
          value: "",
          onchange: (event) => {
            const template = templates.find((item) => item.id === event.target.value);
            if (!template) return;
            values.template_id = template.id;
            values.goal = template.goal || values.goal;
            values.description = template.description || values.description;
            values.category = template.category || values.category;
            values.rules = template.rules || [];
            drawRules();
          },
        }),
        "A template pre-fills the goal and the tool rules; everything stays editable.",
      )
      : null,
    h(
      "div",
      { class: "form-grid" },
      field("Name", input({ placeholder: "Q4 external web", oninput: (event) => (values.name = event.target.value) })),
      field("Category", input({ placeholder: "optional", oninput: (event) => (values.category = event.target.value) })),
      h("div", { class: "full" }, field("Goal", textarea({ placeholder: "Find exposed admin panels and prove one with a screenshot.", oninput: (event) => (values.goal = event.target.value) }))),
      h("div", { class: "full" }, field("Description", textarea({ placeholder: "Operator notes the worker sees as context.", oninput: (event) => (values.description = event.target.value) }))),
      h("div", { class: "full" }, field("Scope", textarea({ placeholder: "acme.test\n10.0.0.0/24", oninput: (event) => (values.scope = event.target.value) }), "One target per line. Every tool call is checked against this and the engagement scope.")),
      field("Token budget", input({ type: "number", placeholder: "500000", oninput: (event) => (values.budgets.tokens = event.target.value) })),
      field("Time budget (seconds)", input({ type: "number", placeholder: "3600", oninput: (event) => (values.budgets.seconds = event.target.value) })),
      field("LLM profile", select([["", "Default router"], ...profiles.map((item) => [item.id, `${item.name} · ${item.model || "unset"}`])], { value: values.profile, onchange: (event) => (values.profile = event.target.value) })),
      field("Timeout (minutes)", input({ type: "number", placeholder: "0 = no timeout", oninput: (event) => (values.timeout_minutes = event.target.value) })),
      h("label", { class: "check" }, h("input", { type: "checkbox", onchange: (event) => (values.rotate = event.target.checked) }), "Rotate across all usable profiles"),
      h("label", { class: "check" }, h("input", { type: "checkbox", onchange: (event) => (values.require_finding = event.target.checked) }), "Do not complete without at least one verified finding"),
      h("label", { class: "check" }, h("input", { type: "checkbox", checked: true, onchange: (event) => (values.start = event.target.checked) }), "Start immediately"),
    ),
    h("div", { class: "stack" }, h("div", { class: "spread" }, h("h3", {}, "Tool approval rules"), h("button", { class: "btn sm", onclick: () => { values.rules.push({ name: "", target: "tool_name", kind: "string", pattern: "", policy: "ask" }); drawRules(); } }, "+ Rule")), form),
  );
  const drawRules = () => {
    mount(
      form,
      values.rules.length
        ? values.rules.map((rule, index) =>
          h(
            "div",
            { class: "row wrap", style: { gap: "6px", alignItems: "flex-end" } },
            h("div", { style: { flex: "1 1 140px" } }, field("Pattern", input({ value: rule.pattern, placeholder: "nmap", oninput: (event) => (rule.pattern = event.target.value) }))),
            h("div", { style: { width: "120px" } }, field("Target", select(["tool_name", "tool_input", "url", "host"], { value: rule.target, onchange: (event) => (rule.target = event.target.value) }))),
            h("div", { style: { width: "110px" } }, field("Match", select(["string", "regex", "argv"], { value: rule.kind, onchange: (event) => (rule.kind = event.target.value) }))),
            h("div", { style: { width: "110px" } }, field("Policy", select(["ask", "allow", "deny"], { value: rule.policy, onchange: (event) => (rule.policy = event.target.value) }))),
            h("button", { class: "btn sm ghost", onclick: () => { values.rules.splice(index, 1); drawRules(); } }, "Remove"),
          ),
        )
        : h("div", { class: "faint" }, "No rules — the engagement default policy applies."),
    );
  };
  drawRules();

  drawer({
    title: "New task",
    subtitle: "Autonomous run inside the engagement scope",
    body,
    footer: [
      h("button", { class: "btn", onclick: () => document.getElementById("overlay").replaceChildren() }, "Cancel"),
      h("button", {
        class: "btn primary",
        onclick: async (event) => {
          if (!values.goal.trim()) {
            toast("A goal is required", "error");
            return;
          }
          event.target.disabled = true;
          try {
            const task = await api.post("/tasks", {
              name: values.name,
              goal: values.goal,
              description: values.description,
              category: values.category,
              scope: values.scope.split("\n").map((line) => line.trim()).filter(Boolean),
              budgets: Object.fromEntries(Object.entries(values.budgets).filter(([, value]) => value !== "")),
              llm_profile_ids: values.profile ? [values.profile] : [],
              llm_rotate: values.rotate,
              timeout_minutes: Number(values.timeout_minutes) || 0,
              require_finding: values.require_finding,
              template_id: values.template_id,
              rules: values.rules.filter((rule) => rule.pattern),
              start: values.start,
            });
            toast("Task created");
            navigate("/tasks/" + task.id);
          } catch (error) {
            toast(error.message, "error");
            event.target.disabled = false;
          }
        },
      }, "Create task"),
    ],
  });
}
