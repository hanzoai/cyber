// Minimal DOM + HTTP toolkit. No framework, no build step: the console is a
// plain ES module app so it runs from any static mount.

const SVG_NS = "http://www.w3.org/2000/svg";

function applyProps(node, props) {
  for (const [key, value] of Object.entries(props || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (key === "class" || key === "className") {
      node.setAttribute("class", Array.isArray(value) ? value.filter(Boolean).join(" ") : value);
    } else if (key === "style" && typeof value === "object") {
      Object.assign(node.style, value);
    } else if (key === "dataset") {
      Object.assign(node.dataset, value);
    } else if (key === "html") {
      node.innerHTML = value;
    } else if (key.startsWith("on") && typeof value === "function") {
      node.addEventListener(key.slice(2).toLowerCase(), value);
    } else if (key === "value" && "value" in node) {
      node.value = value;
    } else if (key === "checked" || key === "disabled" || key === "selected") {
      node[key] = Boolean(value);
    } else if (key === "ref" && typeof value === "function") {
      value(node);
    } else {
      node.setAttribute(key, value === true ? "" : String(value));
    }
  }
}

export function h(tag, props, ...children) {
  const node = document.createElement(tag);
  applyProps(node, props);
  append(node, children);
  return node;
}

export function s(tag, props, ...children) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [key, value] of Object.entries(props || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (key === "html") {
      node.innerHTML = value;
    } else if (key.startsWith("on") && typeof value === "function") node.addEventListener(key.slice(2).toLowerCase(), value);
    else node.setAttribute(key, String(value));
  }
  append(node, children);
  return node;
}

export function append(node, children) {
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || child === false || child === true) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

export function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
  return node;
}

export function mount(node, ...children) {
  clear(node);
  append(node, children);
  return node;
}

export function frag(...children) {
  const out = document.createDocumentFragment();
  append(out, children);
  return out;
}

// --- formatting -------------------------------------------------------------

export const fmt = {
  n(value) {
    if (value === null || value === undefined || value === "") return "0";
    const number = Number(value);
    if (!Number.isFinite(number)) return String(value);
    if (Math.abs(number) >= 1e9) return (number / 1e9).toFixed(1) + "B";
    if (Math.abs(number) >= 1e6) return (number / 1e6).toFixed(1) + "M";
    if (Math.abs(number) >= 1e4) return (number / 1e3).toFixed(1) + "k";
    return number.toLocaleString();
  },
  pct(value) {
    const number = Number(value) || 0;
    return (number <= 1 ? number * 100 : number).toFixed(number < 0.1 && number > 0 ? 1 : 0) + "%";
  },
  bytes(value) {
    const number = Number(value) || 0;
    if (number < 1024) return number + " B";
    if (number < 1024 ** 2) return (number / 1024).toFixed(1) + " KiB";
    if (number < 1024 ** 3) return (number / 1024 ** 2).toFixed(1) + " MiB";
    return (number / 1024 ** 3).toFixed(2) + " GiB";
  },
  ago(value) {
    if (!value) return "—";
    const then = Date.parse(value);
    if (Number.isNaN(then)) return String(value);
    const delta = Math.max(0, (Date.now() - then) / 1000);
    if (delta < 45) return "just now";
    if (delta < 3600) return Math.round(delta / 60) + "m ago";
    if (delta < 86400) return Math.round(delta / 3600) + "h ago";
    if (delta < 604800) return Math.round(delta / 86400) + "d ago";
    return new Date(then).toISOString().slice(0, 10);
  },
  clock(value) {
    if (!value) return "—";
    const then = Date.parse(value);
    if (Number.isNaN(then)) return String(value);
    return new Date(then).toISOString().replace("T", " ").slice(0, 19) + "Z";
  },
  duration(seconds) {
    const total = Math.max(0, Math.round(Number(seconds) || 0));
    if (total < 60) return total + "s";
    if (total < 3600) return Math.floor(total / 60) + "m " + (total % 60) + "s";
    return Math.floor(total / 3600) + "h " + Math.floor((total % 3600) / 60) + "m";
  },
  usd(value) {
    const number = Number(value) || 0;
    return number < 0.01 && number > 0 ? "<$0.01" : "$" + number.toFixed(2);
  },
};

// --- status vocabulary ------------------------------------------------------

const TONE = {
  running: "info",
  queued: "violet",
  paused: "warn",
  completed: "ok",
  failed: "danger",
  stopped: "danger",
  archived: "",
  budget_exhausted: "warn",
  timeout: "warn",
  proposed: "violet",
  done: "ok",
  blocked: "warn",
  cancelled: "",
  pending: "warn",
  approved: "ok",
  denied: "danger",
  timed_out: "danger",
  verified: "ok",
  unverified: "",
  rejected: "danger",
  confirmed: "danger",
  cannot_confirm: "warn",
  not_reproduced: "ok",
  open: "info",
  closed: "",
  critical: "sev-critical",
  high: "sev-high",
  medium: "sev-medium",
  low: "sev-low",
  info: "",
  allowed: "ok",
  deny: "danger",
  ask: "warn",
  allow: "ok",
  active: "ok",
  disabled: "",
  succeeded: "ok",
  delivered: "ok",
  retrying: "warn",
  error: "danger",
  info: "",
  warn: "warn",
  debug: "",
};

export function tone(value) {
  return TONE[String(value || "").toLowerCase()] ?? "";
}

export function badge(label, kind = tone(label), extra) {
  return h("span", { class: ["badge", kind, extra].filter(Boolean).join(" ") }, label ? String(label).replace(/_/g, " ") : "—");
}

export function status(value) {
  return h("span", { class: ["badge", tone(value)].filter(Boolean).join(" ") }, h("span", { class: "dot" }), String(value || "—").replace(/_/g, " "));
}

export function severity(value) {
  return h("span", { class: ["badge", "sev-" + (value || "low")] }, String(value || "info").toUpperCase());
}

// --- HTTP -------------------------------------------------------------------

class HttpError extends Error {
  constructor(status, payload) {
    super(payload?.error?.message || payload?.detail || `HTTP ${status}`);
    this.status = status;
    this.code = payload?.error?.code || "http_error";
    this.details = payload?.error?.details || {};
  }
}

const state = {
  engagement: localStorage.getItem("opencyber.engagement") || "",
  token: localStorage.getItem("opencyber.token") || "",
  theme: localStorage.getItem("opencyber.theme") || "",
  org: localStorage.getItem("opencyber.org") || "",
  user: localStorage.getItem("opencyber.user") || "",
};

export const prefs = {
  get engagement() {
    return state.engagement;
  },
  set engagement(value) {
    state.engagement = value || "";
    if (state.engagement) localStorage.setItem("opencyber.engagement", state.engagement);
    else localStorage.removeItem("opencyber.engagement");
  },
  get token() {
    return state.token;
  },
  set token(value) {
    state.token = value || "";
    if (state.token) localStorage.setItem("opencyber.token", state.token);
    else localStorage.removeItem("opencyber.token");
  },
  get theme() {
    return state.theme;
  },
  set theme(value) {
    state.theme = value || "";
    if (state.theme) localStorage.setItem("opencyber.theme", state.theme);
    else localStorage.removeItem("opencyber.theme");
    document.documentElement.dataset.theme = state.theme;
  },
  get org() {
    return state.org;
  },
  set org(value) {
    state.org = value || "";
    if (state.org) localStorage.setItem("opencyber.org", state.org);
    else localStorage.removeItem("opencyber.org");
  },
  get user() {
    return state.user;
  },
  set user(value) {
    state.user = value || "";
    if (state.user) localStorage.setItem("opencyber.user", state.user);
    else localStorage.removeItem("opencyber.user");
  },
};

function qs(params) {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params || {})) {
    if (value === null || value === undefined || value === "") continue;
    search.set(key, String(value));
  }
  if (state.engagement && !search.has("engagement_id")) search.set("engagement_id", state.engagement);
  const text = search.toString();
  return text ? "?" + text : "";
}

async function request(method, path, body, params) {
  const headers = { accept: "application/json" };
  if (state.token) headers.authorization = "Bearer " + state.token;
  if (body !== undefined) headers["content-type"] = "application/json";
  const response = await fetch("/v1" + path + qs(params), {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const type = response.headers.get("content-type") || "";
  if (!response.ok) {
    let payload = null;
    if (type.includes("json")) payload = await response.json().catch(() => null);
    throw new HttpError(response.status, payload);
  }
  if (type.includes("json")) return response.json();
  return response.text();
}

export const api = {
  get: (path, params) => request("GET", path, undefined, params),
  post: (path, body, params) => request("POST", path, body ?? {}, params),
  put: (path, body, params) => request("PUT", path, body ?? {}, params),
  patch: (path, body, params) => request("PATCH", path, body ?? {}, params),
  del: (path, body, params) => request("DELETE", path, body, params),
  download(path, params) {
    const search = new URLSearchParams({ ...(params || {}) });
    if (state.engagement && !search.has("engagement_id")) search.set("engagement_id", state.engagement);
    return fetch("/v1" + path + "?" + search.toString(), {
      headers: state.token ? { authorization: "Bearer " + state.token } : {},
    });
  },
};

// --- overlays ---------------------------------------------------------------

const overlayRoot = () => document.getElementById("overlay");
const toastRoot = () => document.getElementById("toasts");

export function toast(message, kind = "ok") {
  const node = h(
    "div",
    { class: ["toast", kind === "error" ? "error" : ""].filter(Boolean).join(" ") },
    h("span", { class: "dot" }),
    h("div", {}, String(message)),
  );
  toastRoot().append(node);
  setTimeout(() => node.remove(), kind === "error" ? 7000 : 3600);
}

export function closeOverlay() {
  clear(overlayRoot());
  document.body.style.overflow = "";
  document.dispatchEvent(new CustomEvent("overlay:closed"));
}

export function drawer({ title, subtitle, body, footer, width }) {
  const panel = h(
    "div",
    { class: "drawer" + (width === "narrow" ? " narrow" : ""), role: "dialog", "aria-modal": "true", "aria-label": title },
    h(
      "div",
      { class: "drawer-head" },
      h("div", {}, h("h2", {}, title), subtitle ? h("div", { class: "faint", style: { fontSize: "11.5px" } }, subtitle) : null),
      h("button", { class: "btn ghost icon", "aria-label": "Close", onclick: closeOverlay }, "✕"),
    ),
    h("div", { class: "drawer-body" }, body),
    footer ? h("div", { class: "drawer-foot" }, footer) : null,
  );
  const scrim = h("div", { class: "scrim", onclick: (event) => event.target === scrim && closeOverlay() }, panel);
  mount(overlayRoot(), scrim);
  document.body.style.overflow = "hidden";
  return panel;
}

export function modal({ title, body, footer }) {
  const panel = h(
    "div",
    { class: "modal", role: "dialog", "aria-modal": "true", "aria-label": title },
    h("div", { class: "drawer-head" }, h("h2", {}, title), h("button", { class: "btn ghost icon", onclick: closeOverlay }, "✕")),
    h("div", { class: "drawer-body" }, body),
    footer ? h("div", { class: "drawer-foot" }, footer) : null,
  );
  const scrim = h("div", { class: "modal-scrim", onclick: (event) => event.target === scrim && closeOverlay() }, panel);
  mount(overlayRoot(), scrim);
  document.body.style.overflow = "hidden";
  return panel;
}

export function confirmDialog(message, { title = "Confirm", confirmLabel = "Confirm", danger = false } = {}) {
  return new Promise((resolve) => {
    const done = (value) => {
      closeOverlay();
      resolve(value);
    };
    modal({
      title,
      body: h("p", { style: { margin: 0 } }, message),
      footer: [
        h("button", { class: "btn", onclick: () => done(false) }, "Cancel"),
        h("button", { class: "btn " + (danger ? "danger" : "primary"), onclick: () => done(true) }, confirmLabel),
      ],
    });
  });
}

export function promptDialog({ title, label, value = "", placeholder = "", multiline = false }) {
  return new Promise((resolve) => {
    const input = multiline
      ? h("textarea", { class: "textarea", placeholder, value })
      : h("input", { class: "input", placeholder, value });
    const done = (result) => {
      closeOverlay();
      resolve(result);
    };
    modal({
      title,
      body: h("div", { class: "field" }, h("label", {}, label || ""), input),
      footer: [
        h("button", { class: "btn", onclick: () => done(null) }, "Cancel"),
        h("button", { class: "btn primary", onclick: () => done(input.value) }, "Save"),
      ],
    });
    setTimeout(() => input.focus(), 30);
  });
}

// --- component helpers ------------------------------------------------------

export function field(label, control, hint) {
  return h("div", { class: "field" }, h("label", {}, label), control, hint ? h("span", { class: "hint" }, hint) : null);
}

export function input(props = {}) {
  return h("input", { class: "input", ...props });
}

export function textarea(props = {}) {
  return h("textarea", { class: "textarea", ...props });
}

export function select(options, props = {}) {
  const node = h("select", { class: "select", ...props });
  for (const option of options) {
    const [value, label] = Array.isArray(option) ? option : [option, option];
    node.append(h("option", { value, selected: String(value) === String(props.value ?? "") }, label));
  }
  return node;
}

export function button(label, onclick, kind = "") {
  return h("button", { class: ["btn", kind].filter(Boolean).join(" "), onclick }, label);
}

export function card(title, body, actions) {
  return h(
    "section",
    { class: "card" },
    title ? h("div", { class: "card-head" }, h("h2", {}, title), actions || null) : null,
    body?.classList?.contains("card-body") ? body : h("div", { class: "card-body" }, body),
  );
}

export function stat(label, value, { sub, onclick, href } = {}) {
  return h(
    onclick || href ? "a" : "div",
    {
      class: "card stat" + (onclick || href ? " link" : ""),
      href,
      onclick,
      style: href ? { display: "block" } : null,
    },
    h("div", { class: "label" }, label),
    h("div", { class: "value" }, value),
    sub ? h("div", { class: "sub" }, sub) : null,
  );
}

export function table(columns, rows, { empty = "Nothing here yet.", rowKey, onRow } = {}) {
  const head = h("tr", {}, columns.map((column) => h("th", { class: column.num ? "num" : null }, column.label)));
  const body = h("tbody");
  if (!rows.length) {
    const content = typeof empty === "string" ? h("div", {}, empty) : empty || "Nothing here yet.";
    body.append(h("tr", {}, h("td", { class: "empty", colspan: columns.length }, content)));
  }
  for (const row of rows) {
    const tr = h(
      "tr",
      {
        dataset: rowKey ? { key: rowKey(row) } : undefined,
        style: onRow ? { cursor: "pointer" } : null,
        onclick: onRow ? (event) => onRow(row, event) : undefined,
      },
      columns.map((column) => {
        const value = column.render ? column.render(row) : row[column.key];
        return h("td", { class: [column.num ? "num" : "", column.class || ""].filter(Boolean).join(" ") || null }, value ?? "—");
      }),
    );
    body.append(tr);
  }
  return h("div", { class: "table-wrap" }, h("table", { class: "table" }, h("thead", {}, head), body));
}

export function emptyState(title, detail, action) {
  return h("div", { class: "empty-state" }, h("strong", {}, title), detail ? h("div", {}, detail) : null, action ? h("div", { style: { marginTop: "10px" } }, action) : null);
}

export function kv(pairs) {
  const node = h("dl", { class: "kv" });
  for (const [label, value] of pairs) {
    node.append(h("dt", {}, label), h("dd", {}, value ?? "—"));
  }
  return node;
}

export function progress(fraction, label) {
  const value = Math.max(0, Math.min(1, Number(fraction) || 0));
  return h(
    "div",
    {},
    label ? h("div", { class: "spread", style: { fontSize: "11.5px", marginBottom: "4px" } }, h("span", { class: "muted" }, label), h("span", { class: "mono" }, fmt.pct(value))) : null,
    h("div", { class: "progress" }, h("span", { style: { width: value * 100 + "%" } })),
  );
}

export function code(text, language) {
  return h("pre", { class: "code", dataset: language ? { language } : undefined }, typeof text === "string" ? text : JSON.stringify(text, null, 2));
}

export function skeleton(lines = 3) {
  return h("div", { class: "stack" }, Array.from({ length: lines }, () => h("div", { class: "skeleton" })));
}

export function loading(target) {
  mount(target, h("div", { class: "card" }, h("div", { class: "card-body" }, skeleton(6))));
}

// --- polling ----------------------------------------------------------------

const timers = new Set();

export function every(ms, fn, { immediate = true } = {}) {
  if (immediate) fn();
  const id = setInterval(fn, ms);
  timers.add(id);
  return () => {
    clearInterval(id);
    timers.delete(id);
  };
}

export function clearTimers() {
  for (const id of timers) clearInterval(id);
  timers.clear();
}

// --- tiny event bus ---------------------------------------------------------

const listeners = new Map();

export function on(event, fn) {
  if (!listeners.has(event)) listeners.set(event, new Set());
  listeners.get(event).add(fn);
  return () => listeners.get(event)?.delete(fn);
}

export function emit(event, payload) {
  for (const fn of listeners.get(event) || []) fn(payload);
}

// --- router -----------------------------------------------------------------

export function parseHash() {
  const raw = location.hash.replace(/^#/, "") || "/";
  const [path, query] = raw.split("?");
  return { path: path || "/", params: new URLSearchParams(query || "") };
}

export function navigate(path, params) {
  const search = params ? "?" + new URLSearchParams(params).toString() : "";
  location.hash = path + search;
}

export function link(path, label, className) {
  return h("a", { href: "#" + path, class: className }, label);
}

export function download(blob, filename) {
  const url = URL.createObjectURL(blob);
  const anchor = h("a", { href: url, download: filename });
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

export { HttpError };
