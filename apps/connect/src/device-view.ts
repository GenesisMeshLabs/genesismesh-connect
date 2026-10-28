import { el, input } from "./ui";
import { renderPeers } from "./peers";
import type { Status } from "./device-state";
function text(id: string, value: string) {
  el(id).textContent = value;
}
function date(value?: string | null) {
  return value ? new Date(value).toLocaleString() : "—";
}
export function renderDevice(
  state: Status | null,
  busy: boolean,
  actionError: string,
) {
  const device = state?.device ?? null;
  const supported = state?.supported ?? false;
  const enrolled = !!device?.certificate_id;
  const ready = !!device?.ready;
  const running = !!device?.ticket;
  el("unsupported-section").hidden = !state || supported;
  el("setup-steps").hidden = !supported;
  el("prepare-section").hidden = !supported || !!device || !!state?.problem;
  el("identity-section").hidden = !device;
  el("session-section").hidden = !enrolled;
  el("enroll-form").hidden = enrolled;
  el("enrollment-pending").hidden = !device?.enrollment_pending;
  el("authority-settings").hidden = !device;
  el("bridge-host-section").hidden = !device?.bridge_ticket;
  el("sharing-settings").hidden = !device?.sharing_host;
  text(
    "sharing-state",
    device?.sharing_enabled
      ? running
        ? "Your collection is configured for this session."
        : "Collection configured. Start a session to make it available."
      : "Sharing is disabled.",
  );
  text("sharing-badge", device?.sharing_enabled ? "Configured" : "Disabled");
  text(
    "device-state",
    !state
      ? "Loading your device…"
      : !supported
        ? "This build cannot use a protected device credential store. Raw connection tests remain available."
        : !device
          ? state.problem
            ? "Stored identity needs attention. Your existing profile has been preserved."
            : "Create your identity, join your network, then choose a device."
          : !enrolled
            ? device.authority_configured
              ? "Identity saved. Use your operator's invite to join the network."
              : "Identity saved. Set your desktop authority route in Trust & policies."
            : ready
              ? `Session ready for the selected peer · ${device.received_messages} authenticated messages received`
              : running
                ? "Session suspended. Refresh trust to check whether it can resume."
                : "Enrolled. Choose a peer and start a secure session.",
  );
  const error = actionError || state?.problem || device?.problem || "";
  text("device-error", error);
  el("device-error").hidden = !error;
  el("advanced-error-details").hidden = !error;
  const badge = !state
    ? "Getting ready"
    : !supported
      ? "Connection checks"
      : error
        ? "Needs attention"
        : ready
          ? "Session ready"
          : enrolled
          ? "Joined"
            : device
              ? "Awaiting enrollment"
              : "Setup needed";
  text("connection-badge", badge);
  el("connection-badge").className =
    `pill ${ready ? "good" : error ? "attention" : "muted"}`;
  text(
    "sidebar-state",
    ready ? "Session ready" : enrolled ? "Identity enrolled" : "Device setup",
  );
  el("sidebar-dot").classList.toggle("ready", ready);
  text("network-label", device?.network ?? "Your devices. Your network.");
  text(
    "overview-identity",
    enrolled
      ? "Enrolled"
      : device
        ? "Identity created"
        : !supported && state
          ? "Connection checks"
          : "Not set up",
  );
  text(
    "overview-identity-detail",
    enrolled
      ? `Certificate expires ${date(device?.certificate_expires_at)}`
      : "Your private key stays on this device",
  );
  text(
    "overview-session",
    ready ? "Ready for your peer" : running ? "Suspended" : "Not started",
  );
  text(
    "overview-session-detail",
    ready
      ? `${device!.received_messages} authenticated messages received`
      : "Choose a saved device or use manual session tickets for this diagnostic",
  );
  text(
    "overview-sharing",
    device?.sharing_enabled ? "Collection configured" : "Authority governed",
  );
  text("identity-badge", enrolled ? "Enrolled" : "Prepared");
  for (const [id, done, current] of [
    ["step-prepare", !!device, !device],
    ["step-enroll", enrolled, !!device && !enrolled],
    ["step-connect", ready, enrolled && !ready],
  ] as const) {
    el(id).classList.toggle("done", done);
    el(id).classList.toggle("current", current);
  }
  if (device) {
    input("node-key").value = device.node_public_key;
    text(
      "device-details",
      `${device.network} · ${device.authority_via_bridge ? "Desktop authority bridge" : (device.authority ?? "Authority route needed")}`,
    );
    if (!input("peer-node-key").value && device.peer_node)
      input("peer-node-key").value = device.peer_node;
    text(
      "authority-route-status",
      device.authority_via_bridge
        ? "Using your saved network computer’s desktop bridge"
        : device.local_authority_available
          ? "Using the local authority on this desktop"
          : "Add the operator's desktop key and authority ticket below",
    );
    if (!input("bridge-host-key").value && device.bridge_host_node)
      input("bridge-host-key").value = device.bridge_host_node;
  }
  input("session-ticket").value = device?.ticket ?? "";
  input("authority-ticket").value = device?.bridge_ticket ?? "";
  text("trust-network", device?.network ?? "Not joined");
  text("trust-certificate", device?.certificate_id ?? "Not enrolled");
  text("trust-expires", date(device?.certificate_expires_at));
  text(
    "trust-state",
    ready
      ? "Ready for authenticated operations"
      : running
        ? "Suspended"
        : "Not started",
  );
  text(
    "trust-root",
    device?.root_public_key ?? "Your operator supplies this key during setup.",
  );
  text(
    "trust-observed",
    device?.trust_checkpoint?.observed_at
      ? date(device.trust_checkpoint.observed_at)
      : "No update yet",
  );
  text("trust-crl", String(device?.trust_checkpoint?.crl_sequence ?? "—"));
  text(
    "trust-key-sequence",
    String(device?.trust_checkpoint?.key_sequence ?? "—"),
  );
  const sharing = device?.sharing_config;
  el("policy-details").hidden = !sharing;
  el("policy-empty").hidden = !!sharing;
  text("policy-collection", sharing?.collection_id ?? "—");
  text("policy-id", sharing?.policy_id ?? "—");
  text("policy-attestation", sharing?.attestation_id ?? "—");
  el("files-prerequisite").hidden = ready;
  text(
    "files-prerequisite",
    !supported && state
      ? "This build cannot use authenticated file tests. Use a supported native Connect app."
      : !enrolled
        ? "Join your network in Devices before requesting protected files."
        : "Start a secure session in Devices and add the host's current session ticket first.",
  );
  const disabled = (id: string, value: boolean) => {
    el<HTMLButtonElement>(id).disabled = value;
  };
  disabled("prepare-device", busy || !supported || !!state?.problem);
  disabled(
    "enroll-device",
    busy || !supported || !device?.authority_configured,
  );
  disabled("start-session", busy || !enrolled || running || !supported);
  disabled("stop-session", busy || !running);
  for (const id of ["refresh-trust", "trust-refresh"])
    disabled(id, busy || !enrolled || !supported);
  disabled("select-node-key", !device);
  disabled("select-session-ticket", !running);
  disabled("select-authority-ticket", !device?.bridge_ticket);
  disabled("send-session", busy || !ready);
  disabled("read-file-button", busy || !ready);
  input("peer-node-key").disabled = busy || running;
  disabled("use-bridge", busy || running || !device);
  disabled(
    "use-local-authority",
    busy ||
      running ||
      !device?.authority_via_bridge ||
      !device.local_authority_available,
  );
  text(
    "use-bridge",
    enrolled ? "Use desktop bridge" : "Set desktop connection",
  );
  disabled("enable-sharing", busy || running || !device?.sharing_host);
  disabled("disable-sharing", busy || running || !device?.sharing_enabled);
  renderPeers(device, busy);
}
