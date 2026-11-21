// ATT&CK coverage + advisory checklist, derived from recorded findings.

import { h, mount, api, badge, severity, table, fmt, emptyState, download } from "../lib.js";

const MAP = [
  [/admin|panel|exposed/i, "T1190", "Exploit Public-Facing Application"],
  [/idor|account|auth/i, "T1078", "Valid Accounts"],
  [/xss|inject/i, "T1059", "Command and Scripting"],
  [/ssrf|upload|file/i, "T1190", "Exploit Public-Facing Application"],
  [/credential|jwt|key/i, "T1552.001", "Credentials in Files"],
  [/payment|logic/i, "T1078", "Valid Accounts"],
  [/s3|bucket|storage/i, "T1567", "Exfiltration Over Web Service"],
];

const CHECKLIST = [
  "Remove public access to administrative services",
  "Rotate credentials that existed in plaintext files",
  "Patch internet-facing applications",
  "Monitor LDAP/JNDI and random DNS callbacks",
  "Enforce least-privilege file permissions",
  "Restrict model gateways and review request logs",
  "Enforce mobile device compliance",
  "Validate authorization on every object reference",
];

export async function renderAttack(root, ctx) {
  const findings = (await api.get("/findings", { engagement_id: ctx.engagement }).catch(() => ({ findings: [] }))).findings || [];
  const rows = findings.map((finding) => {
    const hit = MAP.find(([pattern]) => pattern.test(finding.title || "")) || [/.*/, "T1190", "Exploit Public-Facing Application"];
    return { ...finding, technique: hit[1], tactic: hit[2] };
  });
  const checked = new Set();
  mount(
    root,
    h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "ATT&CK & advisory checks"), h("p", {}, "Technique tags derived from verified findings, plus the daily checks from the current federal advisory.")), h("div", { class: "actions" }, h("button", { class: "btn", onclick: async () => { const response = await api.download("/findings/export", { format: "json" }); download(await response.blob(), "attack-findings.json"); } }, "Export findings"))),
    h("div", { class: "grid cols-2" },
      h("div", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Coverage"), h("span", { class: "badge" }, rows.length)), table([
        { label: "Finding", render: (row) => h("a", { href: "#/findings?id=" + row.id }, row.title) },
        { label: "Severity", render: (row) => severity(row.severity) },
        { label: "Technique", render: (row) => h("span", { class: "mono" }, row.technique) },
        { label: "Tactic", render: (row) => row.tactic },
        { label: "Verification", render: (row) => badge(row.verification, row.verification === "verified" ? "ok" : "") },
      ], rows, { empty: "No findings yet.", action: h("a", { class: "btn", href: "#/findings" }, "Open findings") })),
      h("div", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Advisory checks"), h("span", { class: "badge" }, `${checked.size}/${CHECKLIST.length}`)), h("div", { class: "card-body stack" },
        CHECKLIST.map((text, index) => {
          const box = h("input", { type: "checkbox", onchange: (event) => { event.target.checked ? checked.add(index) : checked.delete(index); const badgeEl = document.querySelector("#check-count"); if (badgeEl) badgeEl.textContent = `${checked.size}/${CHECKLIST.length}`; } });
          return h("label", { class: "check" }, box, text);
        }),
        h("div", { id: "check-count", class: "faint" }, `0/${CHECKLIST.length}`),
      )),
    ),
  );
}
