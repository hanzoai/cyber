// Chat: the standard Hanzo composer over an engagement-scoped task thread.

import { h, s, mount, api, status, badge, fmt, navigate, toast, emptyState } from "../lib.js";

const ARROW = '<path d="M12 19V5M5 12l7-7 7 7"/>';

export async function renderChat(root, ctx) {
  let tasks = [];
  try {
    tasks = (await api.get("/tasks", { limit: 200 })).records || [];
  } catch (error) {
    mount(root, h("div", { class: "alert danger" }, error.message));
    return;
  }

  let selected = ctx.params.get("task") || tasks[0]?.id || "";
  if (selected && !tasks.some((task) => task.id === selected)) selected = tasks[0]?.id || "";

  const rail = h("div", { class: "list", style: { overflowY: "auto", flex: 1 } });
  const transcript = h("div", { class: "transcript" });
  const heading = h("div", { class: "card-head" }, h("h2", {}, "Conversation"));
  const composer = h("form", { class: "chat-composer" });
  const field_ = h("textarea", {
    class: "hz-composer-field",
    rows: "1",
    placeholder: "Ask anything about this engagement…",
    "aria-label": "Message the planner",
  });
  const sendButton = h("button", { class: "hz-composer-send", type: "submit", "aria-label": "Send", title: "Send" }, s("svg", { viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", "stroke-width": "2.4", "stroke-linecap": "round", "stroke-linejoin": "round", html: ARROW }));

  function drawRail() {
    mount(
      rail,
      tasks.length
        ? tasks.map((task) =>
          h("div", {
            class: "list-item" + (task.id === selected ? " active" : ""),
            onclick: () => { selected = task.id; drawRail(); drawTranscript(); },
          },
            h("div", { class: "row", style: { justifyContent: "space-between" } }, h("span", { class: "title" }, task.name || task.goal || task.id), status(task.status)),
            h("div", { class: "meta" }, `${task.open_intents || 0} open · ${task.findings || 0} findings · ${fmt.ago(task.created)}`),
          ))
        : emptyState("No tasks", "Create a task to start a conversation.", h("button", { class: "btn primary", onclick: () => navigate("/tasks", { create: "1" }) }, "New task")),
    );
  }

  async function drawTranscript() {
    if (!selected) {
      mount(transcript, emptyState("No task selected", "Pick a task on the right to start a conversation."));
      mount(composer, h("div", { class: "hz-composer", style: { opacity: "0.55", pointerEvents: "none" } },
        h("div", { class: "hz-composer-pill" },
          h("textarea", { class: "hz-composer-field", rows: "1", placeholder: "Select a task to chat…", readonly: true }),
          sendButton,
        ),
      ));
      return;
    }
    const task = tasks.find((item) => item.id === selected);
    mount(heading, h("div", { class: "row", style: { gap: "8px" } },
      h("a", { href: "#/tasks/" + selected, style: { fontWeight: 600 } }, task?.name || selected),
      status(task?.status),
      h("button", { class: "btn sm", style: { marginLeft: "auto" }, onclick: () => send(true) }, "Run one round"),
    ));
    let messages = [];
    try {
      messages = (await api.get(`/tasks/${selected}/messages`)).records || [];
    } catch (error) {
      mount(transcript, h("div", { class: "alert danger" }, error.message));
      return;
    }
    mount(
      transcript,
      messages.length
        ? messages.slice().reverse().map((message) => h("div", { class: "bubble " + (message.role === "operator" ? "user" : "agent") },
          h("div", { class: "who" }, `${message.role === "operator" ? "You" : "Hanzo"} · ${fmt.ago(message.created)}`),
          message.content))
        : emptyState("Nothing said yet", "Operator guidance is recorded as a graph hint so the reasoning stays inspectable."),
    );
    transcript.scrollTop = transcript.scrollHeight;
    mount(
      composer,
      h("div", { class: "hz-composer" },
        h("div", { class: "hz-composer-pill" },
          field_,
          sendButton,
        ),
        h("div", { class: "hz-composer-hint" }, "Enter to send · Shift+Enter for a new line · replies stay inside this engagement"),
      ),
    );
  }

  async function send(run = false) {
    const text = field_.value.trim();
    if (!text || !selected) return;
    field_.value = "";
    field_.style.height = "";
    try {
      await api.post("/chat", { task_id: selected, message: text, run });
      await drawTranscript();
    } catch (error) {
      toast(error.message, "error");
    }
  }

  composer.addEventListener("submit", (event) => { event.preventDefault(); send(); });
  field_.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      event.target.form?.requestSubmit();
    }
  });
  field_.addEventListener("input", () => {
    field_.style.height = "auto";
    field_.style.height = Math.min(120, Math.max(32, field_.scrollHeight)) + "px";
  });

  mount(
    root,
    h("div", { class: "chat-shell" },
      h("div", { class: "chat-main" }, heading, transcript, composer),
      h("div", { class: "chat-list" }, h("div", { class: "card-head" }, h("h2", {}, "Tasks"), h("button", { class: "btn sm", onclick: () => navigate("/tasks", { create: "1" }) }, "+")), rail),
    ),
  );

  drawRail();
  await drawTranscript();
}
