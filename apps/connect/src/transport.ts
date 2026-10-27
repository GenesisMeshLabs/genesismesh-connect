import { invoke } from "@tauri-apps/api/core";
import { copyField, el } from "./ui";
import { record } from "./activity";

interface EndpointStatus {
  endpoint_id: string;
  mode: "local" | "public_relay";
  ticket: string;
  received_probes: number;
}
function element<T extends HTMLElement>(id: string): T {
  const target = document.getElementById(id);
  if (!target) throw new Error("Missing interface element: " + id);
  return target as T;
}
const start = element<HTMLButtonElement>("start");
const stop = element<HTMLButtonElement>("stop");
const send = element<HTMLButtonElement>("send");
const selectTicket = element<HTMLButtonElement>("select-ticket");
const mode = element<HTMLSelectElement>("mode");
const ownTicket = element<HTMLTextAreaElement>("own-ticket");
const status = element("status");
const result = element("result");
let running = false;
let busy = false;
interface Report {
  peer_id: string;
  bytes: number;
  elapsed_ms: number;
  paths: string;
  genesis_mesh_authenticated: false;
}
function clearReport(title: string, badge: string) {
  result.textContent = title;
  el("transport-outcome").textContent = title;
  el("transport-result-badge").textContent = badge;
  el("transport-result-badge").className = "pill muted";
  for (const id of ["transport-path", "transport-latency", "transport-bytes"])
    el(id).textContent = "—";
}

function showEndpoint(value: EndpointStatus | null) {
  running = value !== null;
  start.disabled = running || busy;
  stop.disabled = !running || busy;
  mode.disabled = running || busy;
  send.disabled = !running || busy;
  selectTicket.disabled = !running;
  ownTicket.value = value?.ticket ?? "";
  status.textContent = value
    ? "Running · " +
      value.received_probes +
      " received · " +
      value.endpoint_id.slice(0, 16) +
      "…"
    : "Stopped";
}
async function refresh() {
  if (busy) return;
  try {
    showEndpoint(await invoke<EndpointStatus | null>("endpoint_status"));
  } catch (error) {
    status.textContent = "Status unavailable: " + String(error);
  }
}
async function perform(operation: () => Promise<void>) {
  busy = true;
  start.disabled = stop.disabled = send.disabled = mode.disabled = true;
  try {
    await operation();
  } catch (error) {
    clearReport("Connection needs attention", "Not confirmed");
    result.textContent = "Could not complete: " + String(error);
    el("transport-result-hint").textContent =
      "Keep the other app open, check its current ticket and try again.";
    record("Connection check", "error");
  } finally {
    busy = false;
    await refresh();
  }
}
start.addEventListener(
  "click",
  () =>
    void perform(async () => {
      status.textContent = "Starting…";
      clearReport("Waiting for your next check", "Not tested");
      showEndpoint(
        await invoke<EndpointStatus>("start_endpoint", { mode: mode.value }),
      );
      record(
        "Connection check started",
        "success",
        mode.value === "public_relay"
          ? "Public relay mode enabled; the observed path may still be direct."
          : "Local mode with public relays disabled.",
      );
    }),
);
stop.addEventListener(
  "click",
  () =>
    void perform(async () => {
      await invoke("stop_endpoint");
      showEndpoint(null);
      record("Connection check stopped", "success");
    }),
);
selectTicket.addEventListener("click", () => {
  void copyField("own-ticket");
});
element<HTMLFormElement>("probe-form").addEventListener("submit", (event) => {
  event.preventDefault();
  if (!running || busy) return;
  void perform(async () => {
    result.textContent = "Connecting and waiting for a reply…";
    clearReport("Checking your connection…", "In progress");
    const report = await invoke<Report>("send_probe", {
      ticket: element<HTMLTextAreaElement>("peer-ticket").value.trim(),
      message: element<HTMLInputElement>("message").value,
    });
    result.textContent =
      "Round trip succeeded\n" + JSON.stringify(report, null, 2);
    const selected = report.paths
      .split(", ")
      .find((path) => path.includes("(selected)"));
    const path = selected?.startsWith("relay")
      ? "Public relay"
      : selected?.startsWith("direct")
        ? "Direct"
        : "Not reported";
    el("transport-outcome").textContent = "Your devices can talk";
    el("transport-result-badge").textContent = "Echo verified";
    el("transport-result-badge").className = "pill good";
    el("transport-path").textContent = path;
    el("transport-latency").textContent = `${report.elapsed_ms} ms`;
    el("transport-bytes").textContent = `${report.bytes} bytes`;
    el("transport-result-hint").textContent =
      "The reply matched your test message. This connection check does not authenticate a Genesis Mesh identity.";
    record(
      "Connection check passed",
      "success",
      `${path} path · ${report.elapsed_ms} ms · ${report.bytes} bytes. Connectivity check only.`,
    );
  });
});
document.addEventListener("visibilitychange", () => {
  if (!document.hidden) void refresh();
});
setInterval(() => {
  if (!document.hidden) void refresh();
}, 2000);
void refresh();
