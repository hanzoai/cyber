// System configuration: LLM, agents, MCP, skills, tools, notifications,
// interception, approvals, logs and settings.

import {
  h, mount, api, badge, status, table, fmt, toast, drawer, modal, confirmDialog,
  field, input, textarea, select, code, kv, emptyState, promptDialog, every,
} from "../lib.js";

function page(root, title, description, actions) {
  mount(
    root,
    h("div", { class: "page-head" }, h("div", {}, h("h1", {}, title), description ? h("p", {}, description) : null), h("div", { class: "actions" }, actions || [])),
  );
  const body = h("div", { class: "stack" });
  root.append(body);
  return body;
}

// --- LLM --------------------------------------------------------------------

export async function renderLLM(root) {
  const body = page(root, "LLM", "Profiles, failover order and usage accounting for every model call.", [h("button", { class: "btn primary", onclick: () => editProfile(null, draw) }, "New profile")]);
  const drawerBody = h("div", { class: "grid cols-3", style: { marginBottom: "12px" } });

  async function draw() {
    let payload;
    try {
      payload = await api.get("/llm/profiles");
    } catch (error) {
      mount(body, h("div", { class: "alert danger" }, error.message));
      return;
    }
    const profiles = payload.profiles || [];
    mount(
      drawerBody,
      h("div", { class: "card stat" }, h("div", { class: "label" }, "Profiles"), h("div", { class: "value" }, profiles.length)),
      h("div", { class: "card stat" }, h("div", { class: "label" }, "Usable"), h("div", { class: "value" }, (payload.usable || []).length)),
      h("div", { class: "card stat" }, h("div", { class: "label" }, "Active"), h("div", { class: "value" }, profiles.find((item) => item.active)?.name || "—")),
    );
    mount(
      body,
      drawerBody,
      h(
        "div",
        { class: "card" },
        h("div", { class: "card-head" }, h("h2", {}, "Profiles"), h("button", { class: "btn sm", onclick: async () => { const prompt = await promptDialog({ title: "Test prompt", label: "Prompt", value: "Reply with the single word: ready" }); if (prompt) testProfile(prompt, body); } }, "Test router")),
        table(
          [
            { label: "Name", render: (row) => h("div", {}, h("span", { style: { fontWeight: 500 } }, row.name), row.active ? h("span", { class: "badge ok", style: { marginLeft: "6px" } }, "active") : null, h("div", { class: "faint", style: { fontSize: "11px" } }, row.key_ref || "no key ref")) },
            { label: "Model", render: (row) => h("span", { class: "mono" }, row.model || "—") },
            { label: "Provider", render: (row) => badge(row.provider || "openai-compatible") },
            { label: "Base URL", render: (row) => h("span", { class: "mono faint", style: { fontSize: "11px" } }, (row.base_url || "default").slice(0, 48)) },
            { label: "Limit", render: (row) => (row.rate_per_minute || row.rate_per_second) ? `${row.rate_per_minute || ""}/min` : "none" },
            { label: "Health", render: (row) => badge(row.disabled ? "disabled" : row.cooldown_until ? "cooling down" : "ready", row.disabled || row.cooldown_until ? "warn" : "ok") },
            {
              label: "",
              class: "actions-cell",
              render: (row) => h("div", { class: "row", style: { justifyContent: "flex-end" } },
                !row.active ? h("button", { class: "btn sm", onclick: async () => { await api.post(`/llm/profiles/${row.id}/activate`); toast("Activated " + row.name); draw(); } }, "Activate") : null,
                h("button", { class: "btn sm", onclick: () => editProfile(row, draw) }, "Edit"),
                h("button", { class: "btn sm ghost", onclick: async () => { if (await confirmDialog(`Delete ${row.name}?`, { danger: true, confirmLabel: "Delete" })) { await api.del("/llm/profiles/" + row.id); draw(); } } }, "Delete"),
              ),
            },
          ],
          profiles,
          { empty: "No profiles — the router falls back to the configured default endpoint." },
        ),
      ),
    );
  }

  async function testProfile(prompt, target) {
    try {
      const result = await api.post("/llm/test", { prompt });
      toast(result.ok ? `Reply in ${result.latency_ms}ms: ${result.reply}` : result.error, result.ok ? "ok" : "error");
    } catch (error) {
      toast(error.message, "error");
    }
  }

  await draw();
}

async function editProfile(profile, redraw) {
  const values = {
    name: profile?.name || "",
    provider: profile?.provider || "hanzo",
    model: profile?.model || "",
    base_url: profile?.base_url || "",
    key_ref: profile?.key_ref || "",
    priority: profile?.priority ?? 0,
    pool_enabled: profile?.pool_enabled ?? true,
    rate_per_minute: profile?.rate_per_minute ?? 0,
    context_k: profile?.context_k ?? 128,
    max_output_tokens: profile?.max_output_tokens ?? 0,
    reasoning: profile?.reasoning ?? false,
  };
  const name = input({ value: values.name, placeholder: "primary" });
  const provider = select(["hanzo", "openai", "anthropic", "ollama", "custom"], { value: values.provider });
  const model = input({ value: values.model, placeholder: "qwen3-coder" });
  const baseUrl = input({ value: values.base_url, placeholder: "https://api.hanzo.ai/v1" });
  const keyRef = input({ value: values.key_ref, placeholder: "hanzo/api-key" });
  const priority = input({ type: "number", value: values.priority });
  const rpm = input({ type: "number", value: values.rate_per_minute });
  const context = input({ type: "number", value: values.context_k });
  const maxOutput = input({ type: "number", value: values.max_output_tokens });
  const pool = h("input", { type: "checkbox", checked: values.pool_enabled });
  const reasoning = h("input", { type: "checkbox", checked: values.reasoning });
  drawer({
    title: profile ? "Edit LLM profile" : "New LLM profile",
    body: h("div", { class: "form-grid" },
      field("Name", name), field("Provider", provider),
      h("div", { class: "full" }, field("Model", model)),
      h("div", { class: "full" }, field("Base URL", baseUrl, "Blank uses the provider default.")),
      h("div", { class: "full" }, field("Key reference", keyRef, "A KMS path, never a literal secret.")),
      field("Priority", priority), field("Requests per minute", rpm),
      field("Context (K)", context), field("Max output tokens", maxOutput),
      h("label", { class: "check" }, pool, "Include in rotation"),
      h("label", { class: "check" }, reasoning, "Reasoning model"),
    ),
    footer: [h("button", { class: "btn", onclick: () => document.getElementById("overlay").replaceChildren() }, "Cancel"), h("button", { class: "btn primary", onclick: async () => {
      try {
        const payload = {
          name: name.value, provider: provider.value, model: model.value, base_url: baseUrl.value,
          key_ref: keyRef.value, priority: Number(priority.value) || 0, rate_per_minute: Number(rpm.value) || 0,
          context_k: Number(context.value) || 0, max_output_tokens: Number(maxOutput.value) || 0,
          pool_enabled: pool.checked, reasoning: reasoning.checked,
        };
        if (profile) await api.patch("/llm/profiles/" + profile.id, payload);
        else await api.post("/llm/profiles", payload);
        toast("Profile saved");
        document.getElementById("overlay").replaceChildren();
        redraw();
      } catch (error) {
        toast(error.message, "error");
      }
    } }, "Save")],
  });
}

// --- Agents / MCP / skills / tools ------------------------------------------

export async function renderAgents(root) {
  const body = page(root, "Agents", "Built-in roles and engagement-scoped custom agents.", [h("button", { class: "btn primary", onclick: () => newAgent(draw) }, "New agent")]);
  async function draw() {
    const payload = await api.get("/agents");
    const agents = payload.agents || [];
    mount(
      body,
      h("div", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Agents")),
        table([
          { label: "Key", render: (row) => h("span", { class: "mono" }, row.key) },
          { label: "Name", key: "name" },
          { label: "Type", render: (row) => badge(row.builtin ? "built-in" : "custom", row.builtin ? "violet" : "") },
          { label: "MCP", render: (row) => (row.mcp || []).length ? h("div", { class: "chip-list" }, row.mcp.map((item) => h("span", { class: "chip" }, item))) : "—" },
          { label: "Skills", render: (row) => (row.skills || []).length ? h("div", { class: "chip-list" }, row.skills.map((item) => h("span", { class: "chip" }, item))) : "—" },
          { label: "State", render: (row) => badge(row.enabled === false ? "disabled" : "enabled", row.enabled === false ? "warn" : "ok") },
          { label: "", class: "actions-cell", render: (row) => row.builtin ? null : h("button", { class: "btn sm ghost danger", onclick: async () => { if (await confirmDialog(`Delete ${row.key}?`, { danger: true, confirmLabel: "Delete" })) { await api.del("/agents/" + row.key); draw(); } } }, "Delete") },
        ], [...(payload.builtin || []).map((item) => ({ ...item, builtin: true, enabled: true })), ...agents], { empty: "No custom agents." })),
      h("div", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Built-in roles")), h("div", { class: "card-body" }, h("div", { class: "grid cols-3" }, (payload.builtin || []).map((item) => h("div", { class: "card" }, h("div", { class: "card-body" }, h("h3", {}, item.name), h("p", { class: "muted" }, item.description))))))),
    );
  }
  await draw();
}

function newAgent(redraw) {
  const key = input({ placeholder: "recon_specialist" });
  const name = input({ placeholder: "Recon specialist" });
  const description = textarea({ placeholder: "Focus on passive enumeration and asset discovery." });
  drawer({
    title: "New agent",
    body: h("div", { class: "stack" }, field("Key", key, "lowercase letters, digits and underscores"), field("Name", name), field("Description", description)),
    footer: [h("button", { class: "btn", onclick: () => document.getElementById("overlay").replaceChildren() }, "Cancel"), h("button", { class: "btn primary", onclick: async () => { try { await api.post("/agents", { key: key.value, name: name.value, description: description.value }); toast("Agent created"); document.getElementById("overlay").replaceChildren(); redraw(); } catch (error) { toast(error.message, "error"); } } }, "Create")],
  });
}

export async function renderMCP(root) {
  const body = page(root, "MCP", "External servers plus the native surface registered with this process.", [h("button", { class: "btn primary", onclick: () => newServer(draw) }, "Add server")]);
  async function draw() {
    const payload = await api.get("/mcp");
    const servers = payload.servers || [];
    const native = payload.native || [];
    const byGroup = {};
    for (const item of native) (byGroup[item.group] ||= []).push(item.name);
    mount(
      body,
      h("div", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Configured servers")), table([
        { label: "Name", key: "name" },
        { label: "Transport", render: (row) => badge(row.transport) },
        { label: "Target", render: (row) => h("span", { class: "mono", style: { fontSize: "11px" } }, row.target) },
        { label: "Tools", render: (row) => (row.tools || []).length },
        { label: "State", render: (row) => badge(row.enabled ? "enabled" : "disabled", row.enabled ? "ok" : "warn") },
        { label: "", class: "actions-cell", render: (row) => h("button", { class: "btn sm ghost danger", onclick: async () => { await api.del("/mcp/" + row.id); draw(); } }, "Delete") },
      ], servers, { empty: "No external MCP servers configured." })),
      h("div", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Native surface"), h("span", { class: "badge" }, native.length)), h("div", { class: "card-body" },
        Object.entries(byGroup).sort().map(([group, names]) => h("div", { style: { marginBottom: "10px" } }, h("h3", {}, `${group} (${names.length})`), h("div", { class: "chip-list" }, names.map((name) => h("span", { class: "chip mono" }, name)))))),
      ),
    );
  }
  function newServer(redraw) {
    const name = input({ placeholder: "browser" });
    const transport = select(["stdio", "http", "sse"], { value: "stdio" });
    const target = input({ placeholder: "npx -y @modelcontextprotocol/server-browser" });
    drawer({ title: "Add MCP server", body: h("div", { class: "stack" }, field("Name", name), field("Transport", transport), field("Target", target)), footer: [h("button", { class: "btn", onclick: () => document.getElementById("overlay").replaceChildren() }, "Cancel"), h("button", { class: "btn primary", onclick: async () => { try { await api.post("/mcp", { name: name.value, transport: transport.value, target: target.value }); document.getElementById("overlay").replaceChildren(); redraw(); } catch (error) { toast(error.message, "error"); } } }, "Add")] });
  }
  await draw();
}

export async function renderSkills(root) {
  const body = page(root, "Skills", "Engagement skill library. Files live in the engagement workspace and are surfaced to agents as callable skills.");
  const payload = await api.get("/skills");
  const skills = payload.skills || [];
  mount(body, h("div", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Skills"), h("span", { class: "badge" }, skills.length)), table([
    { label: "Name", render: (row) => h("span", { class: "mono" }, row.name) },
    { label: "Type", render: (row) => badge(row.type || (row.is_dir ? "directory" : "file")) },
    { label: "Size", num: true, render: (row) => row.size != null ? fmt.bytes(row.size) : "—" },
  ], skills, { empty: payload.note || "No skills in this engagement." })));
}

export async function renderTools(root) {
  const body = page(root, "Tools", "Custom tools registered for this engagement.", [h("button", { class: "btn primary", onclick: () => newTool(draw) }, "New tool")]);
  async function draw() {
    const payload = await api.get("/tools/custom");
    mount(body, h("div", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Custom tools")), table([
      { label: "Name", key: "name" },
      { label: "Kind", render: (row) => badge(row.tool_kind) },
      { label: "Config", render: (row) => h("span", { class: "mono faint", style: { fontSize: "11px" } }, JSON.stringify(row.config || {}).slice(0, 90)) },
      { label: "State", render: (row) => badge(row.enabled ? "enabled" : "disabled", row.enabled ? "ok" : "warn") },
      { label: "", class: "actions-cell", render: (row) => h("button", { class: "btn sm ghost danger", onclick: async () => { await api.del("/tools/custom/" + row.id); draw(); } }, "Delete") },
    ], payload.tools || [], { empty: "No custom tools." })));
  }
  function newTool(redraw) {
    const name = input({ placeholder: "my_scanner" });
    const kind = select(["command", "http", "script"], { value: "command" });
    const config = textarea({ placeholder: '{"command":"my-scan --json {target}"}' });
    drawer({ title: "New custom tool", body: h("div", { class: "stack" }, field("Name", name), field("Kind", kind), field("Config (JSON)", config)), footer: [h("button", { class: "btn", onclick: () => document.getElementById("overlay").replaceChildren() }, "Cancel"), h("button", { class: "btn primary", onclick: async () => { try { await api.post("/tools/custom", { name: name.value, tool_kind: kind.value, config: JSON.parse(config.value || "{}") }); document.getElementById("overlay").replaceChildren(); redraw(); } catch (error) { toast(error.message, "error"); } } }, "Create")] });
  }
  await draw();
}

// --- Notifications ----------------------------------------------------------

export async function renderNotify(root) {
  const body = page(root, "Notifications", "Severity-scoped channels, digests and delivery retries.", [h("button", { class: "btn primary", onclick: () => newChannel(draw) }, "New channel")]);
  async function draw() {
    const [channels, deliveries] = await Promise.all([api.get("/notify/channels"), api.get("/notify/deliveries")]);
    mount(
      body,
      h("div", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Channels")), table([
        { label: "Name", key: "name" },
        { label: "Kind", render: (row) => badge(row.kind) },
        { label: "Minimum severity", render: (row) => badge(row.min_severity, row.min_severity === "critical" ? "danger" : "") },
        { label: "Digest", render: (row) => row.digest_seconds ? row.digest_seconds + "s" : "immediate" },
        { label: "State", render: (row) => badge(row.enabled ? "enabled" : "disabled", row.enabled ? "ok" : "warn") },
        { label: "", class: "actions-cell", render: (row) => h("div", { class: "row", style: { justifyContent: "flex-end" } }, h("button", { class: "btn sm", onclick: async () => { await api.post("/notify/test", { channel_id: row.id }); toast("Test delivered"); } }, "Test"), h("button", { class: "btn sm ghost danger", onclick: async () => { await api.del("/notify/channels/" + row.id); draw(); } }, "Delete")) },
      ], channels.channels || [], { empty: "No channels configured." })),
      h("div", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Deliveries"), h("button", { class: "btn sm", onclick: async () => { const result = await api.post("/notify/deliveries"); toast(`Retried ${result.retried || 0}`); draw(); } }, "Retry failed")), table([
        { label: "Channel", render: (row) => h("span", { class: "mono" }, row.channel_id?.slice(0, 12)) },
        { label: "Title", key: "title" },
        { label: "State", render: (row) => status(row.status) },
        { label: "When", render: (row) => fmt.ago(row.created) },
      ], (deliveries.records || []).slice(0, 100), { empty: "Nothing delivered yet." })),
    );
  }
  function newChannel(redraw) {
    const name = input({ placeholder: "slack-security" });
    const kind = select(["generic", "telegram", "dingtalk", "feishu", "wecom", "email"], { value: "generic" });
    const config = textarea({ placeholder: '{"url":"https://..."}' });
    const severity = select(["critical", "high", "medium", "low", "info"], { value: "high" });
    drawer({ title: "New notification channel", body: h("div", { class: "stack" }, field("Name", name), h("div", { class: "grid cols-2" }, field("Kind", kind), field("Min severity", severity)), field("Config (JSON)", config)), footer: [h("button", { class: "btn", onclick: () => document.getElementById("overlay").replaceChildren() }, "Cancel"), h("button", { class: "btn primary", onclick: async () => { try { await api.post("/notify/channels", { name: name.value, kind: kind.value, min_severity: severity.value, config: JSON.parse(config.value || "{}") }); document.getElementById("overlay").replaceChildren(); redraw(); } catch (error) { toast(error.message, "error"); } } }, "Create")] });
  }
  await draw();
}

// --- Intercept / approvals --------------------------------------------------

export async function renderIntercept(root, ctx) {
  const blocked = ctx.path === "/intercept/assets";
  const body = page(root, blocked ? "Blocked targets" : "Intercept", blocked ? "Targets that are refused for every agent and every replay." : "Rules that ask, allow or deny tool calls by name, argument or URL.", [h("button", { class: "btn primary", onclick: () => (blocked ? newTarget(draw) : newRule(draw)) }, blocked ? "Add target" : "Add rule")]);

  async function draw() {
    if (blocked) {
      const payload = await api.get("/intercept/blocked");
      mount(body, h("div", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Blocked targets")), table([
        { label: "Pattern", render: (row) => h("span", { class: "mono" }, row.pattern) },
        { label: "Match", render: (row) => badge(row.match_kind) },
        { label: "Note", key: "note" },
        { label: "", class: "actions-cell", render: (row) => h("button", { class: "btn sm ghost danger", onclick: async () => { await api.del("/intercept/blocked/" + row.id); draw(); } }, "Delete") },
      ], payload.targets || [], { empty: "No blocked targets. Scope checks still apply to every request." })));
      return;
    }
    const [payload, defaults, settings] = await Promise.all([
      api.get("/intercept/rules"), api.get("/intercept/default"),
      api.get("/settings").catch(() => ({ settings: {} })),
    ]);
    const scope = settings.settings?.intercept_scope || [];
    mount(
      body,
      h("div", { class: "card" }, h("div", { class: "card-body" }, h("div", { class: "row wrap" }, h("span", { class: "muted" }, "Default policy"), select(["ask", "allow", "deny"], { value: defaults.policy, style: { width: "120px" }, onchange: async (event) => { await api.put("/intercept/default", { policy: event.target.value }); toast("Default set"); } }), h("span", { class: "muted", style: { marginLeft: "12px" } }, "Gated capabilities"), h("div", { class: "chip-list" }, (scope.length ? scope : ["read", "write", "execute", "network", "secret", "destructive"]).map((item) => h("span", { class: "chip" }, item)))))),
      h("div", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Rules"), h("span", { class: "badge" }, (payload.rules || []).length)), table([
        { label: "Name", key: "name" },
        { label: "Target", render: (row) => badge(row.target) },
        { label: "Match", render: (row) => badge(row.match_kind || row.kind) },
        { label: "Pattern", render: (row) => h("span", { class: "mono", style: { fontSize: "11px" } }, row.pattern) },
        { label: "Policy", render: (row) => badge(row.policy, row.policy === "deny" ? "danger" : row.policy === "allow" ? "ok" : "warn") },
        { label: "Priority", num: true, key: "priority" },
        { label: "", class: "actions-cell", render: (row) => h("button", { class: "btn sm ghost danger", onclick: async () => { await api.del("/intercept/rules/" + row.id); draw(); } }, "Delete") },
      ], payload.rules || [], { empty: "No rules — the default policy applies to all gated calls." })),
    );
  }

  function newRule(redraw) {
    const name = input({ placeholder: "ask before nmap" });
    const target = select(["tool_name", "tool_input", "url", "host"], { value: "tool_name" });
    const kind = select(["string", "regex", "argv"], { value: "string" });
    const pattern = input({ placeholder: "nmap" });
    const policy = select(["ask", "allow", "deny"], { value: "ask" });
    const note = input({ placeholder: "why" });
    drawer({ title: "New intercept rule", body: h("div", { class: "stack" }, field("Name", name), h("div", { class: "form-grid" }, field("Target", target), field("Match", kind), field("Pattern", pattern), field("Policy", policy)), field("Note", note)), footer: [h("button", { class: "btn", onclick: () => document.getElementById("overlay").replaceChildren() }, "Cancel"), h("button", { class: "btn primary", onclick: async () => { try { await api.post("/intercept/rules", { name: name.value, target: target.value, kind: kind.value, pattern: pattern.value, policy: policy.value, note: note.value }); document.getElementById("overlay").replaceChildren(); redraw(); } catch (error) { toast(error.message, "error"); } } }, "Add")] });
  }

  function newTarget(redraw) {
    const pattern = input({ placeholder: "*.internal.example" });
    const kind = select(["fuzzy_domain", "domain", "cidr", "host", "url_prefix"], { value: "fuzzy_domain" });
    const note = input({ placeholder: "out of scope" });
    drawer({ title: "Block a target", body: h("div", { class: "stack" }, field("Pattern", pattern), field("Match", kind), field("Note", note)), footer: [h("button", { class: "btn", onclick: () => document.getElementById("overlay").replaceChildren() }, "Cancel"), h("button", { class: "btn primary", onclick: async () => { try { await api.post("/intercept/blocked", { pattern: pattern.value, kind: kind.value, note: note.value }); document.getElementById("overlay").replaceChildren(); redraw(); } catch (error) { toast(error.message, "error"); } } }, "Block")] });
  }

  await draw();
}

export async function renderApprovals(root) {
  const body = page(root, "Approvals", "Gate decisions for tool calls that need a human. Nothing executes until a decision is recorded.");
  const tableBody = h("div");

  async function draw() {
    let payload;
    try {
      payload = await api.get("/intercept/approvals", { status: "" });
    } catch (error) {
      mount(body, h("div", { class: "alert danger" }, error.message));
      return;
    }
    const pending = payload.pending || [];
    mount(
      body,
      h("div", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Pending"), h("div", { class: "row" }, h("button", { class: "btn sm", onclick: () => decideMany(true) }, "Approve all"), h("button", { class: "btn sm danger", onclick: () => decideMany(false) }, "Deny all"))), table([
        { label: "Tool", render: (row) => h("span", { class: "mono" }, row.tool || (row.arguments || {}).tool_name || "unknown") },
        { label: "Kai", render: (row) => h("span", { class: "badge", title: row.kai_label || "heuristic from prior decisions" }, Number(row.kai_score ?? 0.5).toFixed(2)) },
        { label: "Arguments", render: (row) => h("span", { class: "mono faint", style: { fontSize: "11px" } }, JSON.stringify(row.arguments || {}).slice(0, 120)) },
        { label: "Reason", render: (row) => row.reason || "—" },
        { label: "Task", render: (row) => (row.task_id ? h("a", { class: "mono", href: "#/tasks/" + row.task_id }, row.task_id.slice(0, 10)) : "—") },
        { label: "When", render: (row) => fmt.ago(row.created) },
        { label: "", class: "actions-cell", render: (row) => h("div", { class: "row", style: { justifyContent: "flex-end" } },
          h("button", { class: "btn sm primary", onclick: async () => { await decide(row, true); } }, "Approve"),
          h("button", { class: "btn sm danger", onclick: async () => { await decide(row, false); } }, "Deny"),
          h("button", { class: "btn sm", onclick: async () => { await api.post(`/intercept/approvals/${row.id}/always-allow`); toast("Rule saved"); draw(); } }, "Always allow"),
        ) },
      ], pending, { empty: "No approvals waiting." })),
      h("div", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "History")), table([
        { label: "Tool", render: (row) => h("span", { class: "mono" }, row.tool || "—") },
        { label: "Decision", render: (row) => status(row.status) },
        { label: "By", render: (row) => row.decided_by || "—" },
        { label: "When", render: (row) => fmt.ago(row.created) },
      ], (payload.records || []).slice(0, 100), { empty: "No decisions recorded." })),
    );
  }
  async function decide(row, approved) {
    try {
      await api.post("/intercept/approvals", { approval_id: row.id, approved });
      toast(approved ? "Approved" : "Denied");
      draw();
    } catch (error) {
      toast(error.message, "error");
    }
  }
  async function decideMany(approved) {
    const payload = await api.get("/intercept/approvals", { status: "pending" });
    const ids = (payload.pending || []).map((row) => row.id);
    if (!ids.length) return;
    await api.post("/intercept/approvals", { approval_ids: ids, approved });
    toast(`${ids.length} decisions recorded`);
    draw();
  }
  await draw();
  ctxCleanup(root, draw);
}

function ctxCleanup(root, draw) {
  const stop = every(10000, () => draw().catch(() => {}), { immediate: false });
  const observer = new MutationObserver(() => {
    if (!document.body.contains(root)) {
      stop();
      observer.disconnect();
    }
  });
  observer.observe(document.body, { childList: true, subtree: true });
}

// --- Logs / settings --------------------------------------------------------

export async function renderLogs(root) {
  const body = page(root, "Logs", "Operator-visible control-plane events.", [h("button", { class: "btn", onclick: () => { const node = document.querySelector(".log-line"); node?.scrollIntoView(); } }, "Jump to top")]);
  const level = select([["", "All levels"], ["info", "Info"], ["warn", "Warn"], ["error", "Error"]], { value: "", style: { width: "140px" }, onchange: () => draw() });
  const searchInput = input({ placeholder: "Filter messages", style: { width: "220px" }, oninput: () => draw() });
  body.append(h("div", { class: "row", style: { marginBottom: "10px" } }, level, searchInput));
  const list = h("div");
  body.append(list);
  async function draw() {
    const payload = await api.get("/logs", { level: level.value, q: searchInput.value, limit: 500 });
    mount(list, h("div", { class: "card" }, h("div", { class: "card-body" }, (payload.records || []).slice().reverse().map((row) =>
      h("div", { class: "log-line " + row.level }, h("span", { class: "faint" }, fmt.clock(row.at)), h("span", { class: "lvl" }, row.level.toUpperCase()), h("span", {}, row.message))))));
  }
  await draw();
}

export async function renderSettings(root) {
  const body = page(root, "Settings", "Run limits, request noise and the operator token for this console.");
  async function draw() {
    const payload = await api.get("/settings");
    const settings = payload.settings || {};
    const defaults = payload.defaults || {};
    const noise = input({ value: defaults.noise_profile || "balanced", placeholder: "quiet" });
    const workers = input({ type: "number", value: defaults.worker_concurrency ?? 2 });
    const concurrency = input({ type: "number", value: defaults.task_concurrency_limit ?? 0 });
    const token = input({ type: "password", value: "" , placeholder: "leave blank to keep current" });
    mount(
      body,
      h("div", { class: "grid cols-2" },
        h("div", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Execution")), h("div", { class: "card-body stack" },
          field("Noise profile", noise, "off · quiet · balanced · aggressive"),
          field("Worker concurrency", workers),
          field("Task concurrency limit", concurrency, "0 = unlimited"),
          h("button", { class: "btn primary", onclick: async () => { try { await api.put("/settings", { noise_profile: noise.value, worker_concurrency: Number(workers.value), task_concurrency_limit: Number(concurrency.value) }); toast("Settings saved"); draw(); } catch (error) { toast(error.message, "error"); } } }, "Save"),
        )),
        h("div", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Console")), h("div", { class: "card-body stack" },
          field("Operator token", token, "Set OPENCYBER_CONTROL_TOKEN on the server. The browser stores it locally for Bearer requests."),
          h("button", { class: "btn", onclick: async () => { const value = await import("../lib.js").then((module) => module.promptDialog({ title: "Operator token", label: "Bearer token", value: token.value })); if (value !== null) { (await import("../lib.js")).prefs.token = value; toast("Token stored"); } } }, "Set token"),
          h("div", { class: "faint" }, "Backend: " + (payload.governor?.profile || "unknown") + " · " + (payload.governor?.in_flight ?? 0) + " requests in flight"),
        )),
      ),
      h("div", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Raw settings")), h("div", { class: "card-body" }, code(settings))),
    );
  }
  await draw();
}
