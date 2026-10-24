import { invoke } from "@tauri-apps/api/core";
import "./styles.css";

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

function showEndpoint(value: EndpointStatus | null) {
  running = value !== null;
  start.disabled = running || busy;
  stop.disabled = !running || busy;
  mode.disabled = running || busy;
  send.disabled = !running || busy;
  selectTicket.disabled = !running;
  ownTicket.value = value?.ticket ?? "";
  status.textContent = value
    ? "Running · " + value.received_probes + " received · " + value.endpoint_id.slice(0, 16) + "…"
    : "Stopped";
}
async function refresh() {
  if (busy) return;
  try { showEndpoint(await invoke<EndpointStatus | null>("endpoint_status")); }
  catch (error) { status.textContent = "Status unavailable: " + String(error); }
}
async function perform(operation: () => Promise<void>) {
  busy = true;
  start.disabled = stop.disabled = send.disabled = mode.disabled = true;
  try { await operation(); }
  catch (error) { result.textContent = "Could not complete: " + String(error); }
  finally { busy = false; await refresh(); }
}
start.addEventListener("click", () => void perform(async () => {
  status.textContent = "Starting…";
  showEndpoint(await invoke<EndpointStatus>("start_endpoint", { mode: mode.value }));
}));
stop.addEventListener("click", () => void perform(async () => {
  await invoke("stop_endpoint"); showEndpoint(null);
}));
selectTicket.addEventListener("click", () => {
  ownTicket.focus(); ownTicket.select(); ownTicket.setSelectionRange(0, ownTicket.value.length);
});
element<HTMLFormElement>("probe-form").addEventListener("submit", (event) => {
  event.preventDefault();
  if (!running || busy) return;
  void perform(async () => {
    result.textContent = "Connecting and waiting for a reply…";
    const report = await invoke("send_probe", {
      ticket: element<HTMLTextAreaElement>("peer-ticket").value.trim(),
      message: element<HTMLInputElement>("message").value,
    });
    result.textContent = "Round trip succeeded\n" + JSON.stringify(report, null, 2);
  });
});
document.addEventListener("visibilitychange", () => { if (!document.hidden) void refresh(); });
setInterval(() => { if (!document.hidden) void refresh(); }, 2000);
void refresh();
