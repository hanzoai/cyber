// Engagement dashboard: what is running, what it found, how much it cost.

import { h, mount, api, badge, status, severity, stat, table, fmt, loading, every, link, progress, code, emptyState, skeleton } from "../lib.js";
import { hanzoLogo, openLauncher } from "../shell/index.js";

export async function renderDashboard(root, ctx) {
  loading(root);
  const draw = async () => {
    const [data, settings, engagements] = await Promise.all([
      api.get("/dashboard"),
      api.get("/settings").catch(() => ({ privacy: {} })),
      api.get("/engagements").catch(() => ({ engagements: [] })),
    ]);
    const privacy = settings.privacy || {};
    const engagementName = (engagements.engagements || []).find((item) => item.engagement_id === data.engagement_id)?.name;
    const tasks = data.tasks || {};
    const findingsNode = data.findings || {};
    const assets = data.assets || {};
    const governor = data.governor || {};
    const severityTotal = Object.values(findingsNode.severity || {}).reduce((sum, value) => sum + Number(value || 0), 0) || 1;

    mount(
      root,
      h(
        "div",
        { class: "page-head" },
        h("div", {}, h("h1", {}, engagementName || "Engagement overview"), h("p", {}, data.engagement_id ? `Scoped to ${engagementName || data.engagement_id.slice(0, 18)}` : "All engagements")),
        h(
          "div",
          { class: "actions" },
          h("a", { class: "btn", href: "#/tasks" }, "Tasks"),
          h("a", { class: "btn primary", href: "#/tasks", onclick: (event) => { event.preventDefault(); ctx.navigate("/tasks", { create: "1" }); } }, "New task"),
        ),
      ),
      h(
        "section",
        { class: "card", style: { marginBottom: "12px" } },
        h(
          "div",
          { class: "card-body", style: { display: "flex", alignItems: "center", gap: "16px", flexWrap: "wrap" } },
          h("div", { style: { color: "var(--fg)" } }, hanzoLogo(34)),
          h("div", { style: { flex: "1", minWidth: "260px" } },
            h("h2", {}, "Authorized testing, from one place"),
            h("div", { class: "muted", style: { marginTop: "3px" } }, "Plan bounded engagements, capture proof, verify findings, and replay traffic — every call gated by scope, approvals and a process-wide noise governor."),
          ),
          h("button", { class: "btn primary", onclick: openLauncher }, "Open toolkit"),
        ),
      ),
      h(
        "div",
        { class: "grid cols-5" },
        stat("Tasks", fmt.n(tasks.total), { sub: `${tasks.running || 0} running · ${tasks.paused || 0} paused`, href: "#/tasks" }),
        stat("Findings", fmt.n(findingsNode.total), { sub: `${findingsNode.severity?.critical || 0} critical`, href: "#/findings" }),
        stat("Assets", fmt.n(assets.total), { sub: Object.entries(assets.by_kind || {}).slice(0, 2).map(([kind, count]) => `${count} ${kind}`).join(" · ") || "none yet", href: "#/assets" }),
        stat("Traffic", fmt.n(data.traffic?.total), { sub: "captured exchanges", href: "#/traffic" }),
        stat("Approvals", fmt.n(data.approvals_pending), { sub: "awaiting a decision", href: "#/approvals" }),
      ),
      h(
        "div",
        { class: "grid cols-2", style: { marginTop: "12px" } },
        h(
          "section",
          { class: "card" },
          h("div", { class: "card-head" }, h("h2", {}, "Pentest toolkit"), h("button", { class: "btn sm", onclick: openLauncher }, "All capabilities")),
          h(
            "div",
            { class: "card-body grid cols-3", style: { gap: "8px" } },
            ...[
              ["New engagement", "Scope + approvals", "#/tasks?create=1"],
              ["Traffic replay", "Scope-gated", "#/traffic"],
              ["Findings", "Verbatim proof", "#/findings"],
              ["Asset graph", "Coverage", "#/assets"],
              ["Cloud sandbox", "Agentic launch", "#/cloud"],
              ["Intercept", "Rules + gates", "#/intercept"],
            ].map(([label, detail, href]) => h("a", { class: "btn", href, style: { height: "58px", flexDirection: "column", alignItems: "flex-start", justifyContent: "center", gap: "2px" } }, h("span", { style: { fontWeight: 600 } }, label), h("span", { class: "faint", style: { fontSize: "11px" } }, detail))),
          ),
        ),
        h(
          "section",
          { class: "card" },
          h("div", { class: "card-head" }, h("h2", {}, "Privacy posture"), h("span", { class: "badge", style: { marginLeft: "8px" } }, "no telemetry")),
          h(
            "div",
            { class: "card-body" },
            h("dl", { class: "kv" },
              h("dt", {}, "Model route"), h("dd", {}, h("span", { class: "mono", style: { fontSize: "11.5px" } }, privacy.model_endpoint || "—"), privacy.local_model ? h("span", { class: "badge ok", style: { marginLeft: "6px" } }, "local") : null),
              h("dt", {}, "Scope enforcement"), h("dd", {}, privacy.scope_enforcement ? badge("on", "ok") : badge("off", "warn")),
              h("dt", {}, "Offline mode"), h("dd", {}, privacy.offline ? badge("on", "ok") : badge("off", "")),
              h("dt", {}, "Secrets"), h("dd", {}, privacy.secrets || "KMS references only"),
              h("dt", {}, "Noise profile"), h("dd", {}, badge(privacy.noise_profile || governor.profile?.name || governor.profile?.describe?.().name || "balanced")),
            ),
            h("p", { class: "faint", style: { fontSize: "11.5px", marginBottom: 0 } }, "Anonymous here means no upstream telemetry and no plaintext target credentials in control state. Authorization is still engagement-scoped; do not use this for unapproved targets."),
          ),
        ),
      ),
      h(
        "div",
        { class: "grid cols-2", style: { marginTop: "12px" } },
        h(
          "section",
          { class: "card" },
          h("div", { class: "card-head" }, h("h2", {}, "Severity breakdown"), h("a", { class: "btn sm", href: "#/findings" }, "All findings")),
          h(
            "div",
            { class: "card-body stack" },
            ["critical", "high", "medium", "low"].map((name) => {
              const value = Number(findingsNode.severity?.[name] || 0);
              return h(
                "div",
                { class: "bar-row" },
                h("span", {}, name),
                h("div", { class: "track" }, h("span", { style: { width: Math.round((value / severityTotal) * 100) + "%", background: `var(--sev-${name})` } })),
                h("span", { class: "mono", style: { textAlign: "right" } }, value),
              );
            }),
            h("div", { class: "faint", style: { fontSize: "11.5px" } }, `${severityTotal} finding${severityTotal === 1 ? "" : "s"} recorded`),
          ),
        ),
        h(
          "section",
          { class: "card" },
          h("div", { class: "card-head" }, h("h2", {}, "Budget and noise")),
          h(
            "div",
            { class: "card-body stack" },
            h("div", { class: "row wrap" },
              h("span", { class: "badge" }, "profile " + (governor.profile?.name || governor.profile?.describe?.().name || "balanced")),
              h("span", { class: "badge" }, "in flight " + (governor.in_flight ?? 0)),
              h("span", { class: "badge" }, "waiting " + fmt.n(governor.waiting)),
              h("span", { class: "badge" }, "429s " + fmt.n(governor.throttled)),
            ),
            progress(
              (data.usage?.total_tokens || 0) / Math.max(1, (data.usage?.total_tokens || 0) + 500000),
              `${fmt.n(data.usage?.total_tokens)} tokens over ${fmt.n(data.usage?.calls)} calls`,
            ),
            h(
              "div",
              { class: "grid cols-3" },
              h("div", {}, h("div", { class: "faint" }, "Input"), h("div", { style: { fontSize: "17px", fontWeight: 600 } }, fmt.n(data.usage?.input_tokens))),
              h("div", {}, h("div", { class: "faint" }, "Output"), h("div", { style: { fontSize: "17px", fontWeight: 600 } }, fmt.n(data.usage?.output_tokens))),
              h("div", {}, h("div", { class: "faint" }, "Cache read"), h("div", { style: { fontSize: "17px", fontWeight: 600 } }, fmt.pct(data.usage?.cache_hit_rate || 0))),
            ),
            data.daily?.length ? dailyChart(data.daily) : h("div", { class: "faint" }, "No usage recorded yet."),
          ),
        ),
      ),
      h(
        "div",
        { class: "grid cols-2", style: { marginTop: "12px" } },
        h(
          "section",
          { class: "card" },
          h("div", { class: "card-head" }, h("h2", {}, "Recent tasks"), h("a", { class: "btn sm", href: "#/tasks" }, "Open")),
          table(
            [
              { label: "Task", render: (row) => h("a", { href: "#/tasks/" + row.id, style: { fontWeight: 500 } }, row.name || row.goal || row.id) },
              { label: "Status", render: (row) => status(row.status) },
              { label: "Created", render: (row) => h("span", { class: "muted" }, fmt.ago(row.created)) },
            ],
            tasks.recent || [],
            { empty: "No tasks yet — create one to start an autonomous run." },
          ),
        ),
        h(
          "section",
          { class: "card" },
          h("div", { class: "card-head" }, h("h2", {}, "Recent findings")),
          table(
            [
              { label: "Finding", render: (row) => h("a", { href: "#/findings?id=" + row.id }, row.title) },
              { label: "Severity", render: (row) => severity(row.severity) },
              { label: "When", render: (row) => h("span", { class: "muted" }, fmt.ago(row.created)) },
            ],
            findingsNode.recent || [],
            { empty: "Nothing recorded yet." },
          ),
        ),
      ),
      h(
        "section",
        { class: "card", style: { marginTop: "12px" } },
        h("div", { class: "card-head" }, h("h2", {}, "Event stream"), h("a", { class: "btn sm", href: "#/logs" }, "Logs")),
        table(
          [
            { label: "When", render: (row) => h("span", { class: "muted mono" }, fmt.clock(row.created)) },
            { label: "Kind", render: (row) => badge(row.kind, row.kind?.includes("error") ? "danger" : row.kind?.includes("warn") ? "warn" : "info") },
            { label: "Message", render: (row) => row.message || (row.payload ? JSON.stringify(row.payload).slice(0, 140) : "") },
            { label: "Task", render: (row) => (row.task_id ? h("a", { class: "mono", href: "#/tasks/" + row.task_id }, row.task_id.slice(0, 12)) : "—") },
          ],
          data.events || [],
          { empty: "No events yet." },
        ),
      ),
    );
  };

  await draw();
  ctx.cleanup(every(8000, () => draw().catch(() => {}), { immediate: false }));
}

function dailyChart(daily) {
  const width = 100;
  const max = Math.max(...daily.map((row) => row.input + row.output), 1);
  return h(
    "div",
    {},
    h("div", { class: "faint", style: { fontSize: "11.5px", marginBottom: "4px" } }, "Daily tokens"),
    h(
      "div",
      { style: { display: "flex", alignItems: "flex-end", gap: "3px", height: "64px" } },
      daily.slice(-30).map((row) =>
        h("div", {
          title: `${row.date}: ${fmt.n(row.input)} in / ${fmt.n(row.output)} out`,
          style: { flex: "1", minWidth: "3px", height: Math.max(2, ((row.input + row.output) / max) * 64) + "px", background: "var(--fg-muted)", borderRadius: "2px 2px 0 0", opacity: 0.75 },
        })),
    ),
  );
}
