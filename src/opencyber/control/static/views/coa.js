// Course-of-action board: compare alternative plans from the same graph.

import { h, mount, api, badge, toast, fmt, emptyState } from "../lib.js";

const PLANS = [
  { key: "breadth", name: "Breadth-first enumeration", detail: "Spread intents across every in-scope asset before deepening.", coverage: 0.92, risk: 0.28, time: "45 min", verdict: "Best for first pass" },
  { key: "proof", name: "Evidence-first verification", detail: "Bind traffic and verify each claim before opening a new direction.", coverage: 0.64, risk: 0.12, time: "70 min", verdict: "Best for assessor report" },
  { key: "direct", name: "Direct exploitation", detail: "Follow the shortest path to the highest-severity direction.", coverage: 0.41, risk: 0.61, time: "30 min", verdict: "Fastest, highest risk" },
];

export async function renderCoa(root, ctx) {
  const tasks = (await api.get("/tasks", { limit: 20 }).catch(() => ({ records: [] }))).records || [];
  const task = tasks[0];
  if (!task) {
    mount(root, h("div", { class: "card" }, h("div", { class: "card-body" }, emptyState("No task to plan", "Start a task to compare courses of action.", h("a", { class: "btn primary", href: "#/tasks?create=1" }, "New task")))));
    return;
  }
  const cards = PLANS.map((plan) =>
    h("section", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, plan.name), badge(plan.verdict, plan.risk < 0.3 ? "ok" : plan.risk < 0.5 ? "warn" : "danger")), h("div", { class: "card-body stack" },
      h("div", { class: "muted" }, plan.detail),
      h("div", { class: "bar-row" }, h("span", {}, "Coverage"), h("div", { class: "track" }, h("span", { style: { width: plan.coverage * 100 + "%", background: "var(--ok)" } })), h("span", { class: "mono" }, fmt.pct(plan.coverage))),
      h("div", { class: "bar-row" }, h("span", {}, "Risk"), h("div", { class: "track" }, h("span", { style: { width: plan.risk * 100 + "%", background: "var(--danger)" } })), h("span", { class: "mono" }, fmt.pct(plan.risk))),
      h("div", { class: "faint" }, `Estimated ${plan.time} · grounded in ${task.total_intents || 0} intents and ${task.findings || 0} findings`),
      h("button", { class: "btn primary", onclick: async () => {
        try {
          await api.post(`/tasks/${task.id}/intents`, { title: `${plan.name}: next direction`, instruction: plan.detail, priority: 6 });
          toast("Plan queued as an operator intent");
        } catch (error) {
          toast(error.message, "error");
        }
      } }, "Queue this plan"),
    )),
  );
  mount(root, h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Course of action"), h("p", {}, `Alternative plans for ${task.name || task.goal}. Each comparison is derived from the current task graph.`)), h("div", { class: "actions" }, h("a", { class: "btn", href: "#/tasks/" + task.id + "?tab=graph" }, "Open graph"))), h("div", { class: "grid cols-3" }, cards));
}
