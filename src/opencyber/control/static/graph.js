// Exploration graph and coverage views. The graph is deliberately a DOM/SVG
// hybrid: nodes are real elements so they stay accessible and selectable, the
// edges are one SVG layer behind them, and a layering pass decides positions
// from the edge structure instead of physics.

import { h, s, mount, clear, badge, status, fmt, emptyState } from "./lib.js";

const KIND_COLOR = {
  start: "var(--fg)",
  goal: "var(--ok)",
  intent: "var(--info)",
  fact: "var(--fg-muted)",
  finding: "var(--danger)",
  hint: "var(--warn)",
  digest: "var(--violet)",
};

const NODE_W = 190;
const NODE_H = 58;

function layers(nodes, edges) {
  const byId = new Map(nodes.map((node) => [node.id, node]));
  const parents = new Map(nodes.map((node) => [node.id, []]));
  for (const edge of edges) {
    if (!byId.has(edge.source) || !byId.has(edge.target)) continue;
    parents.get(edge.target).push(edge.source);
  }
  const depth = new Map();
  const walk = (id, seen) => {
    if (depth.has(id)) return depth.get(id);
    if (seen.has(id)) return 0;
    seen.add(id);
    const inbound = parents.get(id) || [];
    const value = inbound.length ? Math.max(...inbound.map((parent) => walk(parent, seen))) + 1 : 0;
    depth.set(id, Math.min(value, 12));
    return depth.get(id);
  };
  for (const node of nodes) walk(node.id, new Set());
  const groups = new Map();
  for (const node of nodes) {
    const index = depth.get(node.id) ?? 0;
    if (!groups.has(index)) groups.set(index, []);
    groups.get(index).push(node);
  }
  return [...groups.entries()].sort((a, b) => a[0] - b[0]);
}

export function graphCanvas(data, { onSelect, height = 520 } = {}) {
  const nodes = data?.nodes || [];
  const edges = data?.edges || [];
  if (!nodes.length) {
    return emptyState("No graph yet", "The graph fills in as the planner dispatches intents and workers record facts.");
  }

  const canvas = h("div", { class: "graph-canvas", style: { height: height + "px" } });
  const svg = s("svg", { class: "graph-svg" });
  const defs = s("defs");
  defs.append(
    s("marker", { id: "arrow", viewBox: "0 0 10 10", refX: "9", refY: "5", markerWidth: "6", markerHeight: "6", orient: "auto-start-reverse" },
      s("path", { d: "M 0 0 L 10 5 L 0 10 z", fill: "var(--border-strong)" })),
  );
  svg.append(defs);
  canvas.append(svg);

  const legend = h("div", { class: "graph-legend" }, Object.entries(KIND_COLOR).map(([kind, color]) =>
    h("span", { class: "item" }, h("span", { class: "kind-dot", style: { background: color } }), kind)));
  canvas.append(legend);

  const view = { x: 0, y: 0, scale: 1, ox: 0, oy: 0 };
  const nodeEls = new Map();
  // Deterministic left-to-right story: goal → intents → facts → findings → hints.
  // A kind with many nodes wraps into extra columns so a single column never
  // overflows the canvas.
  const order = { start: 0, goal: 0, intent: 1, fact: 2, finding: 3, hint: 4, digest: 5 };
  const buckets = new Map();
  for (const node of nodes) {
    const key = order[node.kind] ?? 6;
    if (!buckets.has(key)) buckets.set(key, []);
    buckets.get(key).push(node);
  }
  const columns = [];
  for (const key of [...buckets.keys()].sort((a, b) => a - b)) {
    const items = buckets.get(key);
    for (let i = 0; i < items.length; i += 6) columns.push(items.slice(i, i + 6));
  }
  const colGap = 220;
  const rowGap = 84;
  const positions = new Map();
  columns.forEach((items, column) => {
    items.forEach((node, index) => {
      const spread = (items.length - 1) / 2;
      positions.set(node.id, {
        x: 170 + column * colGap,
        y: height / 2 + (index - spread) * rowGap,
      });
    });
  });
  const content = h("div", { style: { position: "absolute", inset: "0", transformOrigin: "0 0" } });

  function paint() {
    content.style.transform = `translate(${view.x}px, ${view.y}px) scale(${view.scale})`;
  }

  for (const edge of edges) {
    const from = positions.get(edge.source);
    const to = positions.get(edge.target);
    if (!from || !to) continue;
    const midX = (from.x + to.x) / 2;
    svg.append(s("path", {
      d: `M ${from.x} ${from.y} C ${midX} ${from.y}, ${midX} ${to.y}, ${to.x} ${to.y}`,
      fill: "none",
      stroke: "var(--border-strong)",
      "stroke-width": 1.2,
      "marker-end": "url(#arrow)",
      opacity: edge.kind === "spawns" ? 0.45 : 0.75,
      "stroke-dasharray": edge.kind === "derived_from" ? "4 3" : null,
    }));
  }

  for (const node of nodes) {
    const position = positions.get(node.id);
    const el = h(
      "div",
      {
        class: ["graph-node", node.state === "running" ? "running" : "", node.state === "pending" ? "running" : ""].filter(Boolean).join(" "),
        style: { left: position.x + "px", top: position.y + "px", width: NODE_W + "px" },
        dataset: { node: node.id, kind: node.kind },
        role: "button",
        tabindex: "0",
        onclick: (event) => {
          event.stopPropagation();
          for (const item of nodeEls.values()) item.classList.remove("selected");
          el.classList.add("selected");
          onSelect?.(node);
        },
      },
      h("div", { class: "kicker" }, h("span", { class: "kind-dot", style: { background: KIND_COLOR[node.kind] || "var(--fg-muted)" } }), node.kind, node.state ? h("span", { class: "faint" }, "· " + node.state) : null),
      h("div", { class: "summary" }, node.summary || node.label || node.id),
    );
    nodeEls.set(node.id, el);
    content.append(el);
  }
  canvas.append(content);

  const tools = h(
    "div",
    { class: "graph-tools" },
    h("button", { class: "btn sm", onclick: () => { view.scale = Math.min(1.8, view.scale * 1.2); paint(); } }, "Zoom in"),
    h("button", { class: "btn sm", onclick: () => { view.scale = Math.max(0.35, view.scale / 1.2); paint(); } }, "Zoom out"),
    h("button", { class: "btn sm", onclick: () => { view.x = 0; view.y = 0; view.scale = 1; paint(); } }, "Fit"),
  );
  canvas.append(tools);

  let dragging = null;
  canvas.addEventListener("pointerdown", (event) => {
    if (event.target.closest(".graph-node, .graph-tools")) return;
    dragging = { x: event.clientX, y: event.clientY, ox: view.x, oy: view.y };
    canvas.classList.add("dragging");
    canvas.setPointerCapture(event.pointerId);
  });
  canvas.addEventListener("pointermove", (event) => {
    if (!dragging) return;
    view.x = dragging.ox + (event.clientX - dragging.x);
    view.y = dragging.oy + (event.clientY - dragging.y);
    paint();
  });
  canvas.addEventListener("pointerup", () => {
    dragging = null;
    canvas.classList.remove("dragging");
  });
  canvas.addEventListener("wheel", (event) => {
    if (!event.ctrlKey && !event.metaKey) return;
    event.preventDefault();
    view.scale = Math.max(0.35, Math.min(1.8, view.scale * (event.deltaY < 0 ? 1.1 : 0.9)));
    paint();
  }, { passive: false });

  view.scale = columns.length > 5 ? 0.82 : 1;
  paint();
  return canvas;
}

export function graphLegendCounts(data) {
  const counts = data?.counts?.by_kind || {};
  const chips = Object.entries(KIND_COLOR)
    .filter(([kind]) => counts[kind])
    .map(([kind, color]) => h("span", { class: "chip" }, h("span", { class: "kind-dot", style: { background: color, display: "inline-block", width: "7px", height: "7px", borderRadius: "2px", marginRight: "5px" } }), `${kind} ${counts[kind]}`));
  return h("div", { class: "chip-list" }, chips.length ? chips : h("span", { class: "faint" }, "no nodes yet"));
}

// --- coverage ---------------------------------------------------------------

export function coverageBars(coverage) {
  const rows = coverage?.assets || [];
  const total = Number(coverage?.total ?? rows.length);
  const tested = Number(coverage?.tested ?? rows.filter((row) => row.tested).length);
  if (!rows.length) return emptyState("No in-scope assets", "Add assets to the engagement graph to measure coverage.");
  return h(
    "div",
    { class: "stack" },
    h("div", { class: "grid cols-4" },
      h("div", { class: "card stat" }, h("div", { class: "label" }, "Assets"), h("div", { class: "value" }, fmt.n(total))),
      h("div", { class: "card stat" }, h("div", { class: "label" }, "Tested"), h("div", { class: "value" }, fmt.n(tested))),
      h("div", { class: "card stat" }, h("div", { class: "label" }, "Untested"), h("div", { class: "value" }, fmt.n(total - tested))),
      h("div", { class: "card stat" }, h("div", { class: "label" }, "Coverage"), h("div", { class: "value" }, fmt.pct((coverage?.percent ?? 0) / 100))),
    ),
    coverage?.caveat ? h("div", { class: "alert info" }, coverage.caveat) : null,
    h("div", { class: "chip-list" }, rows.slice(0, 400).map((row) =>
      h("span", { class: "chip asset", title: `${row.kind} · ${row.tested ? "tested" : "untested"}`, style: row.tested ? { borderColor: "color-mix(in srgb, var(--ok) 45%, var(--border))" } : { borderStyle: "dashed", color: "var(--fg-muted)" } },
        row.value))),
  );
}

export function assetTree(tree, { onSelect, selected } = {}) {
  const roots = tree?.roots || [];
  if (!roots.length) return emptyState("No assets", "Import or discover assets to build the engagement graph.");

  function node(entry, depth) {
    const row = h(
      "div",
      {
        class: "list-item" + (selected === entry.id ? " active" : ""),
        style: { paddingLeft: 12 + depth * 14 + "px" },
        onclick: () => onSelect?.(entry),
      },
      h("span", { class: "title" }, entry.value),
      h("span", { class: "meta" }, entry.kind, entry.children?.length ? ` · ${entry.children.length} child${entry.children.length === 1 ? "" : "ren"}` : ""),
    );
    const children = (entry.children || []).map((child) => node(child, depth + 1));
    return h("div", {}, row, children);
  }

  return h("div", { class: "list" }, roots.map((root) => node(root, 0)));
}
