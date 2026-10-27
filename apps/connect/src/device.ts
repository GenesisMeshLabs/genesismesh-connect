import { invoke } from "@tauri-apps/api/core";
import { el, input, copyField, notify, showPage } from "./ui";
import { renderDevice } from "./device-view";
import { record } from "./activity";
import type { Status } from "./device-state";
interface Report {
  genesis_mesh_authenticated: boolean;
  peer_node: string;
  bytes: number;
}
interface ReadReport {
  collection_id: string;
  file_name: string;
  bytes: number;
  sha256: string;
  text: string | null;
  receipt_id: string;
}
let state: Status | null = null;
let busy = false;
let polling = false;
let actionError = "";
function render() {
  renderDevice(state, busy, actionError);
}
async function refreshStatus() {
  if (polling) return;
  polling = true;
  try {
    state = await invoke<Status>("device_status");
  } catch (error) {
    state = null;
    actionError = "Device status unavailable: " + String(error);
  } finally {
    polling = false;
    render();
  }
}
async function perform(label: string, operation: () => Promise<string | void>) {
  if (busy) return;
  busy = true;
  actionError = "";
  render();
  try {
    const detail = await operation();
    record(label, "success", detail || "");
  } catch (error) {
    actionError = String(error);
    record(label, "error");
  } finally {
    busy = false;
    await refreshStatus();
    if (actionError) el("device-error").scrollIntoView({ block: "nearest" });
  }
}
function form(
  id: string,
  label: string,
  operation: () => Promise<string | void>,
) {
  el<HTMLFormElement>(id).addEventListener("submit", (event) => {
    event.preventDefault();
    void perform(label, operation);
  });
}
function peerTicket() {
  const ticket = input("session-peer-ticket").value.trim();
  if (!ticket) {
    showPage("device");
    el<HTMLDetailsElement>("session-tickets").open = true;
    input("session-peer-ticket").focus();
    throw new Error(
      "Add the other device's current session ticket under Exchange connection tickets first.",
    );
  }
  return ticket;
}
form("prepare-form", "Device identity created", async () => {
  await invoke("device_prepare", {
    settings: {
      authority:
        el<HTMLSelectElement>("authority-mode").value === "local"
          ? input("authority-url").value.trim()
          : null,
      network: input("network-name").value.trim(),
      root_public_key: input("root-key").value.trim(),
    },
  });
  notify(
    "Identity created. Give your public key to your operator for an invite.",
  );
});
el("authority-mode").addEventListener("change", () => {
  const local = el<HTMLSelectElement>("authority-mode").value === "local";
  el("local-authority-fields").hidden = !local;
  el("remote-prepare-hint").hidden = local;
  el<HTMLInputElement>("authority-url").required = local;
  input("authority-url").disabled = !local;
});
form("enroll-form", "Network enrollment", async () => {
  const invite = input("device-invite").value.trim();
  input("device-invite").value = "";
  await invoke("device_enroll", {
    invite,
    sharingHost: el<HTMLSelectElement>("enrollment-kind").value === "host",
  });
  notify("Device enrolled. Choose the other device's public key to continue.");
});
form("session-form", "Secure session started", async () => {
  await invoke("device_start", { peer: input("peer-node-key").value.trim() });
  el<HTMLDetailsElement>("session-tickets").open = true;
  notify(
    "Session started. Exchange the current tickets with your other device.",
  );
});
el("stop-session").addEventListener(
  "click",
  () =>
    void perform("Session stopped", async () => {
      await invoke("device_stop");
      input("session-peer-ticket").value = "";
    }),
);
for (const id of ["refresh-trust", "trust-refresh"])
  el(id).addEventListener(
    "click",
    () =>
      void perform("Trust refreshed", async () => {
        await invoke("device_refresh");
      }),
  );
form("authority-route-form", "Desktop authority route updated", async () => {
  await invoke("device_use_bridge", {
    route: {
      ticket: input("bridge-host-ticket").value.trim(),
      host_node: input("bridge-host-key").value.trim(),
    },
  });
  input("bridge-host-ticket").value = "";
});
el("use-local-authority").addEventListener(
  "click",
  () =>
    void perform("Local authority selected", async () => {
      await invoke("device_use_local_authority");
    }),
);
form("sharing-form", "Sharing collection configured", async () => {
  await invoke("device_configure_sharing", {
    config: {
      collection_id: input("share-id").value.trim(),
      directory: input("share-directory").value.trim(),
      attestation_id: input("share-attestation").value.trim(),
      policy_id: input("share-policy").value.trim(),
    },
  });
  notify("Collection configured. Start your session to share it.");
});
el("disable-sharing").addEventListener(
  "click",
  () =>
    void perform("Sharing disabled", async () => {
      await invoke("device_configure_sharing", { config: null });
    }),
);
form("read-form", "Protected file read", async () => {
  const ticket = peerTicket();
  el("file-proof").hidden = true;
  el("read-result").textContent =
    "Requesting authorization and verifying the file…";
  try {
    const result = await invoke<ReadReport>("device_read", {
      ticket,
      collectionId: input("read-collection").value.trim(),
      fileName: input("read-file").value.trim(),
      expectedSha256: input("read-version").value.trim().toLowerCase() || null,
    });
    el("file-proof-name").textContent =
      `${result.collection_id} / ${result.file_name}`;
    el("file-proof-size").textContent =
      `${result.bytes.toLocaleString()} bytes`;
    el("file-proof-digest").textContent = result.sha256;
    el("file-proof-receipt").textContent = result.receipt_id;
    el("file-proof").hidden = false;
    el("read-result").textContent =
      result.text ??
      "Binary payload verified. Saving binary files is not available in this preview.";
    return `${result.bytes} bytes verified. Client-verified receipt: ${result.receipt_id}`;
  } catch (error) {
    el("read-result").textContent =
      "No file read was confirmed. A late failure can follow delivery; check the host's receipts before retrying.";
    throw error;
  }
});
form("session-send-form", "Authenticated message", async () => {
  const ticket = peerTicket();
  el("session-result").textContent =
    "Checking the other device's identity and waiting for its reply…";
  try {
    const report = await invoke<Report>("device_send", {
      ticket,
      message: input("session-message").value,
    });
    if (!report.genesis_mesh_authenticated)
      throw new Error("The reply was not Genesis Mesh authenticated.");
    el("session-result").textContent =
      `Authenticated reply received · ${report.bytes} bytes\nPeer: ${report.peer_node}`;
    return `${report.bytes} bytes confirmed after Genesis Mesh authentication. Message content is excluded from activity.`;
  } catch (error) {
    el("session-result").textContent = "Message was not confirmed.";
    throw error;
  }
});
for (const [button, field] of [
  ["select-node-key", "node-key"],
  ["select-session-ticket", "session-ticket"],
  ["select-authority-ticket", "authority-ticket"],
]) {
  el(button!).addEventListener("click", () => void copyField(field!));
}
document.addEventListener("visibilitychange", () => {
  if (!document.hidden) {
    if (state?.device?.ticket && !busy)
      void perform("Trust refreshed after reopening", async () => {
        await invoke("device_refresh");
      });
    else void refreshStatus();
  }
});
setInterval(() => {
  if (!document.hidden && !busy) void refreshStatus();
}, 2000);
void refreshStatus();
