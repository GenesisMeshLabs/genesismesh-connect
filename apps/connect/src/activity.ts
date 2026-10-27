import { el } from "./ui";
type Outcome = "success" | "error";
interface Event {
  at: Date;
  title: string;
  detail: string;
  outcome: Outcome;
}
const events: Event[] = [];
export function record(title: string, outcome: Outcome, detail = "") {
  events.unshift({ at: new Date(), title, detail, outcome });
  events.splice(50);
  renderActivity();
}
function renderActivity() {
  const filter = el<HTMLSelectElement>("activity-filter").value;
  const visible = events.filter(
    (event) => filter === "all" || event.outcome === filter,
  );
  el("activity-count").textContent =
    `${events.length} event${events.length === 1 ? "" : "s"}`;
  el("activity-empty").hidden = visible.length > 0;
  const list = el("activity-list");
  list.replaceChildren();
  for (const event of visible) {
    const item = document.createElement("li");
    item.className = "activity-item";
    item.dataset.outcome = event.outcome;
    const symbol = document.createElement("span");
    symbol.className = "activity-symbol";
    symbol.textContent = event.outcome === "success" ? "✓" : "!";
    symbol.setAttribute("aria-hidden", "true");
    const body = document.createElement("div");
    const title = document.createElement("strong");
    title.textContent = event.title;
    const detail = document.createElement("p");
    detail.textContent =
      event.detail ||
      (event.outcome === "success"
        ? "Completed in this app session."
        : "The operation was not confirmed. Check the current device status before retrying.");
    body.append(title, detail);
    const time = document.createElement("time");
    time.dateTime = event.at.toISOString();
    time.textContent = event.at.toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
    });
    item.append(symbol, body, time);
    list.append(item);
  }
}
el("activity-filter").addEventListener("change", renderActivity);
