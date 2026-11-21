// Cloud launch: one action provisions an agentic sandbox on Hanzo platform.

import {
  h, mount, api, badge, status, fmt, toast, drawer, field, input, select,
  code, emptyState, every, confirmDialog,
} from "../lib.js";

export async function renderCloud(root, ctx) {
  const state = { config: null, launches: [], selected: null };
  const form = h("div", { class: "stack" });
  const list = h("div", { class: "stack" });
  mount(root, h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Cloud sandbox"), h("p", {}, "Launch an isolated, authorized testing workspace in your own Hanzo org. Secrets are sealed in KMS; the console never stores them.")), h("div", { class: "actions" }, h("a", { class: "btn", href: "#/settings" }, "Tokens"))), form, list);

  async function load() {
    state.config = await api.get("/cloud/config");
    state.launches = (await api.get("/cloud/launches")).launches || [];
  }

  async function draw() {
    try {
      await load();
    } catch (error) {
      mount(form, h("div", { class: "alert danger" }, error.message));
      return;
    }
    const cfg = state.config;
    const name = input({ placeholder: "oc-pentest-01", value: "" });
    const profile = select(Object.entries(cfg.profiles || {}).map(([key, value]) => [key, `${key} — ${value.description}`]), { value: "agentic-pentest" });
    const image = input({ value: cfg.default_image || "" });
    const token = input({ type: "password", placeholder: "generated if blank" });
    const shape = select(["auto", "small", "medium", "large"], { value: "auto" });
    const extra = h("textarea", { class: "textarea", placeholder: '{"CUSTOM_FLAG":"1"}', style: { minHeight: "60px" } });

    mount(
      form,
      h("div", { class: "grid cols-2" },
        h("div", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Launch"), cfg.configured ? badge("IAM ready", "ok") : badge("IAM token missing", "warn")), h("div", { class: "card-body stack" },
          cfg.configured ? null : h("div", { class: "alert warn" }, `Set HANZO_PLATFORM_TOKEN (or HANZO_TOKEN) on the control host. Target: ${cfg.platform_url}`),
          field("Run name", name, "Lowercase slug. Re-running the same name updates the sandbox in place."),
          h("div", { class: "grid cols-2" }, field("Profile", profile), field("Shape", shape)),
          field("Image", image, "Must expose the control plane on port 8787."),
          field("Control token", token, "Write-only. Sealed into KMS and returned once on launch."),
          field("Extra environment (JSON)", extra),
          h("button", {
            class: "btn primary",
            disabled: !cfg.configured,
            onclick: async (event) => {
              event.target.disabled = true;
              try {
                let env = {};
                if (extra.value.trim()) env = JSON.parse(extra.value);
                const result = await api.post("/cloud/launch", { name: name.value, profile: profile.value, image: image.value, shape: shape.value, control_token: token.value, env });
                toast(`Launched ${result.launch.name}`);
                if (result.control_token_once) {
                  drawer({
                    title: "Save this control token",
                    body: h("div", { class: "stack" }, h("p", { class: "muted" }, "It is sealed into KMS and shown once. The console cannot read it back."), code(result.control_token_once)),
                    footer: [h("button", { class: "btn primary", onclick: () => document.getElementById("overlay").replaceChildren() }, "Saved")],
                  });
                }
                state.selected = result.launch.id;
                draw();
              } catch (error) {
                toast(error.message, "error");
                event.target.disabled = false;
              }
            },
          }, "Launch sandbox"),
        )),
        h("div", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Profiles")), h("div", { class: "card-body stack" }, Object.entries(cfg.profiles || {}).map(([key, value]) =>
          h("div", {}, h("h3", {}, key), h("div", { class: "muted" }, value.description), h("div", { class: "chip-list" }, Object.entries(value.env || {}).map(([envKey, envValue]) => h("span", { class: "chip mono" }, `${envKey}=${envValue}`))))))),
      ),
    );

    const rows = state.launches.map((row) =>
      h(
        "tr",
        {},
        h("td", {}, h("span", { class: "mono" }, row.name)),
        h("td", {}, badge(row.profile)),
        h("td", {}, status(row.status)),
        h("td", {}, row.url ? h("a", { href: row.url, target: "_blank", rel: "noreferrer", class: "mono" }, row.url.replace(/^https?:\/\//, "").slice(0, 36)) : "—"),
        h("td", {}, fmt.ago(row.created)),
        h("td", { class: "actions-cell" }, h(
          "div",
          { class: "row", style: { justifyContent: "flex-end" } },
          h("button", { class: "btn sm", onclick: () => openDetail(row) }, "Details"),
          h("button", { class: "btn sm ghost danger", onclick: async () => { if (await confirmDialog(`Stop ${row.name}?`, { danger: true, confirmLabel: "Stop" })) { await api.post(`/cloud/launches/${row.id}/stop`); draw(); } } }, "Stop"),
        )),
      ),
    );
    const table = h(
      "div",
      { class: "card" },
      h("div", { class: "card-head" }, h("h2", {}, "Launches"), h("span", { class: "badge" }, state.launches.length)),
      state.launches.length
        ? h("div", { class: "table-wrap" }, h("table", { class: "table" }, h("thead", {}, h("tr", {}, ["Name", "Profile", "Status", "URL", "When", ""].map((label) => h("th", {}, label)))), h("tbody", {}, rows)))
        : emptyState("No cloud sandboxes", "Launch a sandbox above, or start a local task to test inside this host.", h("a", { class: "btn", href: "#/tasks?create=1" }, "Start task")),
    );
    mount(list, table);

    if (state.selected) {
      const row = state.launches.find((item) => item.id === state.selected);
      if (row) openDetail(row);
    }
  }

  async function openDetail(row) {
    let payload;
    try {
      payload = await api.get(`/cloud/launches/${row.id}/status`);
    } catch (error) {
      toast(error.message, "error");
      return;
    }
    const logsButton = h("button", { class: "btn sm", onclick: async () => {
      const logs = await api.get(`/cloud/launches/${row.id}/logs`);
      mount(logPane, h("div", { class: "stack" }, h("div", { class: "faint" }, `deployment ${logs.deployment || "—"}`), code((logs.logs || []).map((line) => typeof line === "string" ? line : JSON.stringify(line)).join("\n") || "no logs yet")));
    } }, "Refresh logs");
    const logPane = h("div");
    drawer({
      title: row.name,
      subtitle: row.profile + " · " + row.image,
      body: h("div", { class: "stack" },
        h("div", { class: "row wrap" }, status(payload.launch?.status || row.status), payload.available ? badge("platform reachable", "ok") : badge("platform offline", "warn")),
        h("dl", { class: "kv" }, h("dt", {}, "URL"), h("dd", {}, row.url ? h("a", { href: row.url, target: "_blank", rel: "noreferrer" }, row.url) : "—"), h("dt", {}, "Platform ID"), h("dd", { class: "mono" }, row.platform_id || "—"), h("dt", {}, "Engagement"), h("dd", { class: "mono" }, row.engagement_id || "—")),
        h("div", { class: "row" }, logsButton),
        logPane,
      ),
      footer: [h("button", { class: "btn", onclick: () => document.getElementById("overlay").replaceChildren() }, "Close")],
    });
  }

  await draw();
  ctx.cleanup(every(15000, () => draw().catch(() => {}), { immediate: false }));
}
