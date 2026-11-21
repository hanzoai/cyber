// Operator console shell: navigation, routing and the engagement selector.
// Every view talks to the same JSON API an external client would use.

import {
  h, s, mount, clear, api, prefs, navigate, parseHash, toast, badge, status,
  closeOverlay, clearTimers, every, emit, on, link, fmt,
} from "./lib.js";
import { renderDashboard } from "./views/dashboard.js";
import { renderTasks } from "./views/tasks.js";
import { renderTask } from "./views/task.js";
import { renderFindings } from "./views/findings.js";
import { renderTraffic } from "./views/traffic.js";
import { renderChat } from "./views/chat.js";
import { renderAgents, renderApprovals, renderIntercept, renderLLM, renderLogs, renderMCP, renderNotify, renderSettings } from "./views/system.js";
import { renderAssets, renderExecutions, renderSync, renderUsage, renderWorkspace, renderTemplates } from "./views/misc.js";
import { renderCloud } from "./views/cloud.js";
import { renderAttack } from "./views/attack.js";
import { renderCoa } from "./views/coa.js";
import { renderTools, renderSkills, renderSecurity, renderSbom, renderHardening, renderScanner } from "./views/kitchen.js";
import { renderWiring } from "./views/wiring.js";
import { NAV, renderSidebar, renderSidebarFooter, renderTopbar, openLauncher } from "./shell/index.js";

const ROUTES = [
  { match: /^\/$/, view: renderDashboard, title: "Dashboard", nav: "dashboard" },
  { match: /^\/chat$/, view: renderChat, title: "Chat", nav: "chat" },
  { match: /^\/tasks$/, view: renderTasks, title: "Tasks", nav: "tasks" },
  { match: /^\/tasks\/(?<task>[^/]+)$/, view: renderTask, title: "Task", nav: "tasks" },
  { match: /^\/findings$/, view: renderFindings, title: "Findings", nav: "findings" },
  { match: /^\/traffic$/, view: renderTraffic, title: "Traffic", nav: "traffic" },
  { match: /^\/commands$/, view: renderExecutions, title: "Commands", nav: "commands" },
  { match: /^\/llm-records$/, view: renderUsage, title: "LLM records", nav: "records" },
  { match: /^\/assets$/, view: renderAssets, title: "Assets", nav: "assets" },
  { match: /^\/sync$/, view: renderSync, title: "Sync", nav: "sync" },
  { match: /^\/workspace$/, view: renderWorkspace, title: "Workspace", nav: "workspace" },
  { match: /^\/templates$/, view: renderTemplates, title: "Templates", nav: "tasks" },
  { match: /^\/llm$/, view: renderLLM, title: "LLM", nav: "llm" },
  { match: /^\/agents$/, view: renderAgents, title: "Agents", nav: "agents" },
  { match: /^\/mcp$/, view: renderMCP, title: "MCP", nav: "mcp" },
  { match: /^\/skills$/, view: renderSkills, title: "Skills", nav: "skills" },
  { match: /^\/tools$/, view: renderTools, title: "Tools", nav: "tools" },
  { match: /^\/notify$/, view: renderNotify, title: "Notify", nav: "notify" },
  { match: /^\/intercept$/, view: renderIntercept, title: "Intercept", nav: "intercept" },
  { match: /^\/intercept\/assets$/, view: renderIntercept, title: "Blocked targets", nav: "intercept-assets", tab: "blocked" },
  { match: /^\/approvals$/, view: renderApprovals, title: "Approvals", nav: "approvals" },
  { match: /^\/logs$/, view: renderLogs, title: "Logs", nav: "logs" },
  { match: /^\/settings$/, view: renderSettings, title: "Settings", nav: "settings" },
  { match: /^\/cloud$/, view: renderCloud, title: "Cloud sandbox", nav: "cloud" },
  { match: /^\/attack$/, view: renderAttack, title: "ATT&CK & checks", nav: "attack" },
  { match: /^\/coa$/, view: renderCoa, title: "Course of action", nav: "coa" },
  { match: /^\/security$/, view: renderSecurity, title: "Secret scanning", nav: "security" },
  { match: /^\/sbom$/, view: renderSbom, title: "SBOM", nav: "sbom" },
  { match: /^\/hardening$/, view: renderHardening, title: "Linux hardening", nav: "hardening" },
  { match: /^\/scanner$/, view: renderScanner, title: "Capture & scanner", nav: "scanner" },
  { match: /^\/wiring$/, view: renderWiring, title: "Native wiring", nav: "wiring" },
];

const state = {
  counts: {},
  engagements: [],
  current: null,
  stops: [],
  busy: false,
};

function stopView() {
  for (const stop of state.stops.splice(0)) {
    try {
      stop();
    } catch {
      /* a view teardown must not break navigation */
    }
  }
  clearTimers();
  closeOverlay();
}

function cleanup(fn) {
  if (typeof fn === "function") state.stops.push(fn);
}

// --- shell ------------------------------------------------------------------

function toggleTheme() {
  prefs.theme = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
}

async function createEngagement() {
  const { promptDialog } = await import("./lib.js");
  const name = await promptDialog({ title: "New engagement", label: "Name", placeholder: "Acme Q4 external" });
  if (!name) return;
  const targets = await promptDialog({ title: "Scope", label: "Targets, comma separated", placeholder: "acme.test, 10.0.0.0/24" });
  try {
    const record = await api.post("/engagements", { name, targets: String(targets || "").split(",").map((item) => item.trim()).filter(Boolean) });
    toast("Engagement " + record.engagement_id + " created");
    prefs.engagement = record.engagement_id;
    await loadEngagements();
    render();
  } catch (error) {
    toast(error.message, "error");
  }
}

async function loadEngagements() {
  try {
    const payload = await api.get("/engagements");
    state.engagements = Array.isArray(payload) ? payload : payload.engagements || [];
  } catch (error) {
    state.engagements = [];
    if (error.status !== 401) toast("Could not load engagements: " + error.message, "error");
  }
  if (prefs.engagement && !state.engagements.some((item) => item.engagement_id === prefs.engagement)) prefs.engagement = "";
}

async function refreshCounts() {
  try {
    const stats = await api.get("/stats");
    state.counts = { findings: stats.findings, approvals: stats.approvals_pending, tasks: stats.tasks };
    const sidebar = document.getElementById("sidebar");
    if (sidebar.childElementCount) {
      renderSidebar(sidebar, { nav: state.current?.nav, counts: state.counts });
      renderSidebarFooter(document.getElementById("sidebar-footer"), {
        org: prefs.org || "admin",
        user: prefs.user || "z@hanzo.ai",
        onOrg: () => openLauncher(),
        onUser: () => { location.hash = "#/settings"; },
      });
    }
  } catch {
    /* counts are decoration */
  }
}

// --- routing ----------------------------------------------------------------

async function render() {
  const { path, params } = parseHash();
  const route = ROUTES.find((entry) => entry.match.test(path)) || ROUTES[0];
  state.current = { ...route, params, path };
  stopView();
  renderSidebar(document.getElementById("sidebar"), { nav: route.nav, counts: state.counts });
  renderSidebarFooter(document.getElementById("sidebar-footer"), {
    org: prefs.org || "admin",
    user: prefs.user || "z@hanzo.ai",
    onOrg: () => openLauncher(),
    onUser: () => { location.hash = "#/settings"; },
  });
  renderTopbar(document.getElementById("topbar"), {
    title: route.title,
    engagements: state.engagements,
    engagement: prefs.engagement,
    onNew: createEngagement,
    onLaunch: () => { location.hash = "#/cloud"; },
    onToggleNav: () => document.getElementById("app").classList.toggle("collapsed"),
    onToggleTheme: toggleTheme,
  });
  const root = document.getElementById("view");
  document.title = (route.title === "Dashboard" ? "OpenCyber" : route.title + " · OpenCyber");
  const ctx = {
    params,
    path,
    task: route.match.exec(path)?.groups?.task || "",
    navigate,
    cleanup,
    refreshShell: async () => {
      await refreshCounts();
    },
    engagement: prefs.engagement,
  };
  try {
    await route.view(root, ctx);
  } catch (error) {
    if (error.status === 401) {
      mount(root, h("div", { class: "card" }, h("div", { class: "card-body" }, h("h2", {}, "Token required"), h("p", { class: "muted" }, "This control plane requires an operator token. Set it under Settings."), h("a", { class: "btn primary", href: "#/settings" }, "Open settings"))));
    } else {
      mount(root, h("div", { class: "card" }, h("div", { class: "card-body" }, h("h2", {}, "Could not render this view"), h("pre", { class: "code" }, String(error?.stack || error)))));
    }
  }
  root.focus?.({ preventScroll: true });
  await refreshCounts();
}

window.addEventListener("hashchange", render);
window.addEventListener("DOMContentLoaded", async () => {
  prefs.theme = prefs.theme || "dark";
  document.documentElement.dataset.theme = prefs.theme;
  await loadEngagements();
  try {
    const identity = await api.get("/whoami");
    if (identity.org) prefs.org = identity.org;
    if (identity.user) prefs.user = identity.user;
  } catch { /* local mode has no IAM */ }
  await render();
  setInterval(refreshCounts, 15000);
  window.addEventListener("keydown", (event) => {
    if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
      event.preventDefault();
      openLauncher();
    }
  });
});
