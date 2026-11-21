/*
 * One shell for every cyber capability: tasks, findings, traffic, assets and
 * the agentic sandbox. Geometry and color come from tokens.css; this module
 * owns only structure and behavior, so a host with @hanzo/gui loaded themes it
 * without a single duplicate declaration.
 */

import { h, s, mount, toast, drawer, field, input, select, prefs, navigate } from "../lib.js";

const GLYPH = {
  dashboard: '<path d="M3 3h7v7H3zM14 3h7v4h-7zM14 10h7v11h-7zM3 13h7v8H3z"/>',
  chat: '<path d="M4 4h16v12H8l-4 4z"/>',
  tasks: '<path d="M4 6h16M4 12h16M4 18h10"/>',
  findings: '<path d="M12 3l9 16H3zM12 9v5M12 16v1"/>',
  traffic: '<path d="M3 12h4l3-7 4 14 3-7h4"/>',
  commands: '<path d="M4 5h16v14H4zM7 9l3 3-3 3M13 15h4"/>',
  records: '<path d="M6 3h9l3 3v15H6zM9 9h6M9 13h6M9 17h3"/>',
  assets: '<path d="M4 5h6v6H4zM14 5h6v6h-6zM9 15h6v6H9z"/>',
  sync: '<path d="M4 12a8 8 0 0 1 13-6M20 12a8 8 0 0 1-13 6M4 5v4h4M20 19v-4h-4"/>',
  workspace: '<path d="M3 6h6l2 2h10v11H3z"/>',
  llm: '<path d="M12 3v4M12 17v4M5 12H3M21 12h-2M7 7L5 5M17 7l2-2M7 17l-2 2M17 17l2 2M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8z"/>',
  agents: '<path d="M12 4a3 3 0 1 1 0 6 3 3 0 0 1 0-6zM5 21v-2a5 5 0 0 1 5-5h4a5 5 0 0 1 5 5v2"/>',
  mcp: '<path d="M4 7h16v4H4zM4 13h16v4H4z"/>',
  skills: '<path d="M12 3l3 6 6 1-4.5 4.5L18 21l-6-3-6 3 1.5-6.5L3 10l6-1z"/>',
  tools: '<path d="M14 4l6 6-4 4-6-6zM4 20l6-6"/>',
  notify: '<path d="M6 16V9a6 6 0 1 1 12 0v7l2 3H4zM10 21h4"/>',
  intercept: '<path d="M12 3l8 4v6c0 5-3.5 7-8 8-4.5-1-8-3-8-8V7z"/>',
  approvals: '<path d="M5 12l4 4L19 6"/>',
  logs: '<path d="M4 5h16M4 9h16M4 13h10M4 17h7"/>',
  settings: '<path d="M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6zM12 2v3M12 19v3M2 12h3M19 12h3M5 5l2 2M17 17l2 2M5 19l2-2M17 7l2-2"/>',
  templates: '<path d="M4 4h16v4H4zM4 10h7v10H4zM13 10h7v10h-7z"/>',
  cloud: '<path d="M6 18h12a4 4 0 0 0 0-8 6 6 0 0 0-11-2 4 4 0 0 0-1 10z"/>',
  scanner: '<path d="M4 12h2l2-6 3 12 3-9 2 3h4"/>',
  security: '<path d="M12 3l7 3v5c0 5-3 7-7 8-4-1-7-3-7-8V6zM9 12l2 2 4-4"/>',
  sbom: '<path d="M4 5h6v6H4zM14 5h6v6h-6zM4 13h6v6H4zM14 13h6v6h-6z"/>',
  hardening: '<path d="M12 3l8 3v5c0 5-3 8-8 10-5-2-8-5-8-10V6zM9 12l2 2 4-4"/>',
  coa: '<path d="M4 6h16M4 12h10M4 18h13M17 9l3 3-3 3"/>',
  attack: '<path d="M12 3v18M5 8l14 8M19 8L5 16M12 3l-2 3M12 3l2 3"/>',
  wiring: '<path d="M4 7h4v4H4zM16 13h4v4h-4zM8 9h4v4H8zM12 13h4M16 15h0"/>',
  launcher: '<path d="M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h6v6h-6z"/>',
};

export const NAV = [
  {
    title: "Run",
    items: [
      { id: "dashboard", label: "Dashboard", path: "/" },
      { id: "chat", label: "Chat", path: "/chat" },
      { id: "tasks", label: "Tasks", path: "/tasks" },
      { id: "cloud", label: "Cloud sandbox", path: "/cloud" },
    ],
  },
  {
    title: "Evidence",
    items: [
      { id: "findings", label: "Findings", path: "/findings", count: "findings" },
      { id: "traffic", label: "Traffic", path: "/traffic" },
      { id: "scanner", label: "Capture & scanner", path: "/scanner" },
      { id: "assets", label: "Assets", path: "/assets" },
      { id: "commands", label: "Commands", path: "/commands" },
      { id: "records", label: "LLM records", path: "/llm-records" },
    ],
  },
  {
    title: "Control",
    items: [
      { id: "intercept", label: "Intercept", path: "/intercept" },
      { id: "intercept-assets", label: "Blocked targets", path: "/intercept/assets" },
      { id: "approvals", label: "Approvals", path: "/approvals", count: "approvals" },
      { id: "attack", label: "ATT&CK & checks", path: "/attack" },
      { id: "coa", label: "Course of action", path: "/coa" },
      { id: "security", label: "Secret scanning", path: "/security" },
      { id: "sbom", label: "SBOM", path: "/sbom" },
      { id: "hardening", label: "Linux hardening", path: "/hardening" },
      { id: "wiring", label: "Native wiring", path: "/wiring" },
      { id: "workspace", label: "Workspace", path: "/workspace" },
      { id: "sync", label: "Sync", path: "/sync" },
    ],
  },
  {
    title: "System",
    collapsible: true,
    items: [
      { id: "llm", label: "LLM", path: "/llm" },
      { id: "agents", label: "Agents", path: "/agents" },
      { id: "mcp", label: "MCP", path: "/mcp" },
      { id: "skills", label: "Skills", path: "/skills" },
      { id: "tools", label: "Tools", path: "/tools" },
      { id: "notify", label: "Notify", path: "/notify" },
      { id: "templates", label: "Templates", path: "/templates" },
      { id: "logs", label: "Logs", path: "/logs" },
      { id: "settings", label: "Settings", path: "/settings" },
    ],
  },
];

export const LAUNCHER = [
  { key: "tasks", label: "Tasks", detail: "Autonomous engagements", path: "/tasks", glyph: "tasks" },
  { key: "findings", label: "Findings", detail: "Verified evidence", path: "/findings", glyph: "findings" },
  { key: "traffic", label: "Traffic", detail: "Capture and replay", path: "/traffic", glyph: "traffic" },
  { key: "assets", label: "Assets", detail: "Engagement graph", path: "/assets", glyph: "assets" },
  { key: "cloud", label: "Cloud sandbox", detail: "Launch agentic pentest", path: "/cloud", glyph: "cloud" },
  { key: "settings", label: "Settings", detail: "Profile and tokens", path: "/settings", glyph: "settings" },
];

// Official @hanzo/logo geometry (v1.0.26), inlined so it themes from
// currentColor and needs no image request or CSS framework.
const HANZO_LOGO_PATHS = [
  "M22.21 67V44.6369H0V67H22.21Z",
  "M0 44.6369L22.21 46.8285V44.6369H0Z",
  "M66.7038 22.3184H22.2534L0.0878906 44.6367H44.4634L66.7038 22.3184Z",
  "M22.21 0H0V22.3184H22.21V0Z",
  "M66.7198 0H44.5098V22.3184H66.7198V0Z",
  "M66.6753 22.3185L44.5098 20.0822V22.3185H66.6753Z",
  "M66.7198 67V44.6369H44.5098V67H66.7198Z",
];

export function hanzoLogo(size = 22) {
  const svg = s("svg", { width: size, height: size, viewBox: "0 0 67 67", fill: "currentColor", "aria-hidden": "true" });
  for (const d of HANZO_LOGO_PATHS) svg.append(s("path", { d }));
  return svg;
}

export function glyph(name) {
  return s("svg", { viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", "stroke-width": "1.6", "stroke-linecap": "round", "stroke-linejoin": "round", html: GLYPH[name] || GLYPH.launcher });
}

export function brand() {
  return h(
    "div",
    { class: "brand" },
    h("div", { class: "brand-mark", style: { borderRadius: "8px", background: "transparent", color: "var(--fg)", width: "28px", height: "28px" } }, hanzoLogo(22)),
    h("div", { class: "brand-text" }, "Cyber", h("small", {}, "OpenCyber control")),
  );
}

export function renderSidebarFooter(node, { org = "admin", user = "z@hanzo.ai", onOrg, onUser } = {}) {
  mount(
    node,
    h("div", { class: "hz-sidebar-footer" },
      h("button", { class: "hz-org", title: "Organization", onclick: onOrg || (() => openLauncher()) },
        h("span", { class: "hz-org-mark" }, String(org || "?").slice(0, 1).toUpperCase()),
        h("span", { class: "hz-org-name" }, org || "personal"),
        glyph("launcher"),
      ),
      h("button", { class: "hz-account", title: "Account", onclick: onUser || (() => { location.hash = "#/settings"; }) },
        h("span", { class: "hz-avatar" }, String(user || "?").slice(0, 2).toUpperCase()),
        h("span", { style: { display: "flex", flexDirection: "column", alignItems: "flex-start", minWidth: 0 } },
          h("span", { class: "hz-account-name" }, String(user || "").split("@")[0] || "operator"),
          h("span", { class: "hz-account-mail" }, user || "local"),
        ),
        glyph("settings"),
      ),
    ),
  );
}

export function renderSidebar(node, { nav = "", counts = {} } = {}) {
  const groups = NAV.map((group) => {
    const items = h(
      "div",
      { class: "nav-items" },
      group.items.map((item) =>
        h(
          "a",
          { class: "nav-item" + (nav === item.id ? " active" : ""), href: "#" + item.path, dataset: { nav: item.id }, title: item.label },
          glyph(item.id === "intercept-assets" ? "intercept" : item.id),
          h("span", { class: "nav-label" }, item.label),
          item.count && counts[item.count] ? h("span", { class: "nav-count" }, String(counts[item.count])) : null,
        ),
      ),
    );
    const wrapper = h("div", { class: "nav-group" });
    const title = group.collapsible
      ? h("button", { class: "nav-group-title nav-group-toggle", "aria-expanded": "true", onclick: () => {
          const hidden = wrapper.classList.toggle("collapsed");
          title.setAttribute("aria-expanded", String(!hidden));
          localStorage.setItem("opencyber.system-collapsed", hidden ? "1" : "0");
        } }, group.title, h("span", { class: "nav-chevron" }, "▾"))
      : h("div", { class: "nav-group-title" }, group.title);
    wrapper.append(title, items);
    if (group.collapsible && localStorage.getItem("opencyber.system-collapsed") === "1") {
      wrapper.classList.add("collapsed");
      title.setAttribute("aria-expanded", "false");
    }
    return wrapper;
  });
  mount(node, brand(), groups, h("div", { id: "sidebar-footer", class: "hz-sidebar-footer-slot" }));
}

export function renderTopbar(node, { title = "Dashboard", engagements = [], engagement = "", onNew, onLaunch, onToggleNav, onToggleTheme } = {}) {
  const selectNode = h("select", { class: "select", "aria-label": "Engagement", style: { width: "210px" }, onchange: (event) => { prefs.engagement = event.target.value; location.reload(); } });
  selectNode.append(h("option", { value: "" }, engagements.length ? "All engagements" : "No engagement"));
  for (const item of engagements) {
    selectNode.append(h("option", { value: item.engagement_id, selected: item.engagement_id === engagement }, `${item.name} · ${item.engagement_id.slice(0, 8)}`));
  }
  mount(
    node,
    h("button", { class: "btn ghost icon", "aria-label": "Toggle navigation", onclick: onToggleNav }, "☰"),
    h("div", { class: "crumbs" }, h("a", { href: "#/", class: "faint" }, "Cyber"), h("span", { class: "faint" }, "/"), h("strong", {}, title)),
    h("div", { class: "spacer" }),
    selectNode,
    h("button", { class: "btn sm", onclick: onNew }, "+ Engagement"),
    h("button", { class: "btn sm primary", onclick: onLaunch, dataset: { action: "launch" } }, glyph("cloud"), h("span", {}, "Launch")),
    h("button", { class: "btn ghost icon", "aria-label": "Toggle theme", onclick: onToggleTheme }, "◐"),
  );
}

export function openLauncher() {
  drawer({
    title: "Cyber capabilities",
    subtitle: "One shell for every OpenCyber surface",
    width: "narrow",
    body: h("div", { class: "grid cols-2" }, LAUNCHER.map((item) =>
      h("button", {
        class: "btn",
        style: { height: "72px", flexDirection: "column", alignItems: "flex-start", justifyContent: "center", gap: "4px", borderRadius: "var(--radius-card)" },
        onclick: () => { location.hash = "#" + item.path; document.getElementById("overlay").replaceChildren(); },
      }, glyph(item.glyph), h("span", { style: { fontWeight: 600 } }, item.label), h("span", { class: "faint", style: { fontSize: "11px" } }, item.detail)),
    )),
    footer: [h("button", { class: "btn", onclick: () => document.getElementById("overlay").replaceChildren() }, "Close")],
  });
}
