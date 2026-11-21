// Native wiring status: IAM identity, KMS, storage, sandbox, platform, scope.

import { h, mount, api, badge } from "../lib.js";

export async function renderWiring(root) {
  const [wiring, who, secrets] = await Promise.all([
    api.get("/wiring"),
    api.get("/whoami").catch(() => ({})),
    api.get("/secrets/status").catch(() => ({ key_refs: [] })),
  ]);
  mount(
    root,
    h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Native wiring"), h("p", {}, "Live status of Hanzo IAM, KMS, Base persistence, the agentic sandbox and enforcement gates."))),
    h("div", { class: "grid cols-4" },
      h("div", { class: "card stat" }, h("div", { class: "label" }, "Identity"), h("div", { class: "value", style: { fontSize: "15px" } }, who.user || "unknown"), h("div", { class: "sub" }, `${who.org || "—"} · ${who.mode || "—"}`)),
      h("div", { class: "card stat" }, h("div", { class: "label" }, "Storage"), h("div", { class: "value", style: { fontSize: "15px" } }, wiring.storage?.backend || "—"), h("div", { class: "sub" }, (wiring.storage?.base_url || "local document store").replace(/^https?:\/\//, "").slice(0, 34))),
      h("div", { class: "card stat" }, h("div", { class: "label" }, "Sandbox"), h("div", { class: "value", style: { fontSize: "15px" } }, wiring.sandbox?.mode || "—"), h("div", { class: "sub" }, `${wiring.sandbox?.launches || 0} launches`)),
      h("div", { class: "card stat" }, h("div", { class: "label" }, "Enforcement"), h("div", { class: "value" }, h("div", { class: "row wrap" }, badge(wiring.enforcement?.scope ? "scope on" : "scope off", wiring.enforcement?.scope ? "ok" : "warn"), badge(wiring.enforcement?.offline ? "offline" : "online", wiring.enforcement?.offline ? "ok" : "")))),
    ),
    h("div", { class: "grid cols-3" },
      h("div", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "IAM"), badge(wiring.iam?.mode || "—", "info")), h("div", { class: "card-body" }, h("dl", { class: "kv" }, h("dt", {}, "Mode"), h("dd", {}, wiring.iam?.mode || "—"), h("dt", {}, "Endpoint"), h("dd", { class: "mono", style: { fontSize: "11px" } }, wiring.iam?.url || "—"), h("dt", {}, "Configured"), h("dd", {}, wiring.iam?.configured ? badge("yes", "ok") : badge("no", "warn"))))),
      h("div", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "KMS"), badge(wiring.kms?.mode || "—", "violet")), h("div", { class: "card-body" }, h("dl", { class: "kv" }, h("dt", {}, "Mode"), h("dd", {}, wiring.kms?.mode || "—"), h("dt", {}, "Org / env"), h("dd", {}, `${wiring.kms?.org || "—"} / ${wiring.kms?.env || "—"}`), h("dt", {}, "Configured"), h("dd", {}, wiring.kms?.configured ? badge("yes", "ok") : badge("env only", "warn"))))),
      h("div", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Platform"), badge(wiring.platform?.configured ? "ready" : "missing", wiring.platform?.configured ? "ok" : "warn")), h("div", { class: "card-body" }, h("dl", { class: "kv" }, h("dt", {}, "Endpoint"), h("dd", { class: "mono", style: { fontSize: "11px" } }, wiring.platform?.url || "—"), h("dt", {}, "Token"), h("dd", {}, wiring.platform?.configured ? badge("set (never shown)", "ok") : badge("unset", "warn"))))),
    ),
    h("div", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Key references"), h("span", { class: "badge" }, (secrets.key_refs || []).length)), h("div", { class: "card-body" }, h("p", { class: "muted" }, secrets.note || "Values are resolved at call time and never stored."), h("div", { class: "grid cols-3" }, (secrets.key_refs || []).map((item) => h("div", { class: "chip mono" }, `${item.profile}: ${item.key_ref || "unset"}`))))),
  );
}
