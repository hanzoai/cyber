// Small dialogs shared by the asset, task and traffic views.

import { h, api, drawer, toast, field, input, textarea, select, badge } from "./lib.js";

const KINDS = ["root_domain", "subdomain", "host", "ip", "cidr", "url", "service", "port", "endpoint", "repository", "credential", "cloud_account"];

export function attachAssetsDialog(taskId) {
  const kind = select(KINDS, { value: "subdomain" });
  const values = textarea({ placeholder: "app.acme.test\napi.acme.test", style: { minHeight: "110px" } });
  drawer({
    title: "Attach assets to this task",
    body: h("div", { class: "stack" }, h("div", { class: "grid cols-2" }, field("Kind", kind)), field("Values", values, "One value per line.")),
    footer: [h("button", { class: "btn primary", onclick: async () => {
      try {
        const list = values.value.split("\n").map((line) => line.trim()).filter(Boolean);
        await api.post(`/tasks/${taskId}/assets`, { assets: list.map((value) => ({ kind: kind.value, value })) });
        toast(list.length + " asset(s) anchored");
        document.getElementById("overlay").replaceChildren();
        location.reload();
      } catch (error) {
        toast(error.message, "error");
      }
    } }, "Attach")],
  });
}

export function bindTrafficDialog(exchangeId) {
  const findingId = input({ placeholder: "finding id" });
  const role = select([["supporting", "supporting"], ["proof", "proof"], ["request", "request"], ["response", "response"]], { value: "proof" });
  drawer({
    title: "Bind exchange to a finding",
    body: h("div", { class: "stack" }, field("Finding", findingId), field("Role", role)),
    footer: [h("button", { class: "btn primary", onclick: async () => {
      try {
        await api.post("/findings/" + findingId.value + "/traffic", { exchange_ids: [exchangeId], role: role.value });
        toast("Bound");
        document.getElementById("overlay").replaceChildren();
      } catch (error) {
        toast(error.message, "error");
      }
    } }, "Bind")],
  });
}

export { attachAssetsDialog as addAssetsDialog };
