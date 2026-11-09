import { setupServices } from "./services";
import { setupActivity } from "./access-activity";
import { setupHostAdministration } from "./host-admin";
import { setupClientAdministration } from "./client-admin";
import {setupClientRequests} from "./client-requests";
import { visibleSpaces, sortedFiles, type LibraryFilter } from "./library-state";
import { setupSharing } from "./sharing";
import { sharingChoices } from "./sharing-state";
import { invoke, isTauri } from "@tauri-apps/api/core";
import { getCurrent, onOpenUrl } from "@tauri-apps/plugin-deep-link";
import QRCode from "qrcode";
import { el, input, showPage } from "./ui";
import { fillIcons, icon, type IconName } from "./icons";
import { setupAdvanced } from "./advanced";
import { PLACE_KEY, place, readPlace, resumeTo, type View } from "./resume-state";
import { availability, recoveryReminder, recoveryStatus, restoredMessage, RECOVERY_SAVED_KEY } from "./setup-state";
import { EXPLAIN_AFTER_MS, STOPPED, finishingDetail, finishingTitle, stoppedWaiting, waitDetail, waitTitle } from "./waiting";
import {
  primaryScreen,
  isService,
  filterFiles,
  formatBytes,
  folderCrumbs,
  friendlyProblem,
  connectionSummary,
  spaceSummary,
  sendSummary,
  filesEmptyText,
  newAsks,
  type HomeSpace,
  type HomeStatus,
  type FilePage,
  type FileEntry,
} from "./home-state";

fillIcons();
let current: HomeStatus | null = null;
let currentView="files";
let libraryFilter: LibraryFilter = "all";
let statusProblem: string | null = null;
let screen = "welcome",
  busy = false,
  polling = false;
let invitation = "",
  expiresAt = 0,
  approval = "";
let downloadId = "";
// A stop asked for before a download has its ID, made as soon as it has one:
// going back keeps it to continue later, Cancel drops it.
let pendingStop: "keep" | "discard" | null = null;
// A connection choice being made is not replaced by the next status poll.
let connectionDirty = false;
let folderPath: string[] = [];
// The shared folder being browsed; null for the selected device's only one.
let currentSpace: HomeSpace | null = null;
let page: FilePage | null = null,
  files: FileEntry[] = [];
const localName = () =>
  localStorage.getItem("connect.friendly-name") ||
  (/iPhone|iPad/.test(navigator.userAgent) ? "My iPhone"
    : /Android/.test(navigator.userAgent) ? "My Android device"
      : /Macintosh/.test(navigator.userAgent) ? "My Mac"
        : "My computer");
input("computer-name").value = localName();
input("join-name").value = localName();
input("friendly-name").value = localName();
function text(id: string, value: string) {
  el(id).textContent = value;
}
function setIcon(id: string, name: IconName) {
  const slot = el(id);
  if (slot.dataset.icon === name) return;
  slot.dataset.icon = name;
  slot.replaceChildren(icon(name));
}
/** An icon on a tinted tile, leading a row or a quick action. */
function tile(name: IconName) {
  const span = document.createElement("span");
  span.className = "row-tile";
  span.append(icon(name));
  return span;
}
/** A ⋯ menu with an item's less common actions; destructive ones last. */
function menu(title: string, items: { label: string; danger?: boolean; action: () => Promise<void> }[], disabled: boolean) {
  const options = document.createElement("details");
  options.className = "row-menu";
  const summary = document.createElement("summary");
  summary.setAttribute("aria-label", `More options for ${title}`);
  summary.append(icon("more"));
  const list = document.createElement("div");
  list.className = "menu";
  for (const item of items) {
    const button = document.createElement("button");
    button.textContent = item.label;
    if (item.danger) button.className = "danger";
    button.disabled = disabled;
    button.addEventListener("click", () => {
      options.open = false;
      void run(button, item.action);
    });
    list.append(button);
  }
  options.append(summary, list);
  return options;
}
// An open menu closes when tapping anywhere else.
document.addEventListener("click", (event) => {
  for (const open of document.querySelectorAll<HTMLDetailsElement>("details.row-menu[open]"))
    if (!open.contains(event.target as Node)) open.open = false;
});
function visible(id: string, value: boolean) {
  el(id).hidden = !value;
}
function message(value: string) {
  text("home-message", value);
  visible("home-message", !!value);
}
function problem(value: string) {
  text("home-error", value ? friendlyProblem(value) : "");
  text("last-error-detail", value);
  visible("home-error", !!value);
}
function show(next: string) {
  screen = next;
  for (const name of [
    "startup",
    "welcome",
    "create-screen",
    "join-screen",
    "restore-screen",
    "joining-screen",
    "workspace",
  ])
    visible(name, name === next);
  text("home-title", next === "workspace" ? titles[currentView] : "Connect");
}
const titles: Record<string, string> = { files: "Shared", devices: "Devices", activity: "Activity", settings: "Settings" };
function selectView(next: string) {
  if(next!=="devices"){hostAdministration.close();clientAdministration.close();clientRequests.close();}
  // An unsaved connection choice is dropped when leaving Settings.
  if (next !== "settings") connectionChanged(false);
  currentView=next;
  remember();
  text("home-title", titles[next]);
  for (const name of ["files", "devices", "activity", "settings"])
    visible(`view-${name}`, name === next);
  for (const button of document.querySelectorAll<HTMLElement>("[data-view]"))
    button.setAttribute("aria-pressed", String(button.dataset.view === next));
  if(next==="activity")void activity.open();else activity.close();
}
async function run(button: HTMLButtonElement, action: () => Promise<void>) {
  if (busy) return;
  busy = true;
  button.disabled = true;
  button.setAttribute("aria-busy", "true");
  const label = [...button.childNodes];
  if (!button.childElementCount) button.textContent = "Please wait…";
  problem("");
  try {
    await action();
    await refresh();
  } catch (error) {
    problem(String(error));
  } finally {
    busy = false;
    button.disabled = false;
    button.removeAttribute("aria-busy");
    button.replaceChildren(...label);
  }
}
/** Requests from devices and agents, for the owner to answer. */
function renderAsks(status: HomeStatus) {
  const asks = status.owner ? status.asks ?? [] : [];
  visible("asks-card", asks.length > 0);
  const list = el("asks-list");
  list.replaceChildren();
  for (const ask of asks) {
    const item = document.createElement("div");
    item.className = "ask";
    const who = document.createElement("strong");
    who.textContent = `${ask.name} asks for access`;
    const words = document.createElement("blockquote");
    words.textContent = ask.text;
    const share = document.createElement("button");
    share.textContent = "Share";
    share.addEventListener("click", () =>
      sharing.shareWith(ask.node, () =>
        void invoke("ask_close", { id: ask.id }).then(refresh),
      ),
    );
    const decline = document.createElement("button");
    decline.className = "secondary";
    decline.textContent = "Decline";
    decline.addEventListener("click", () =>
      void run(decline, async () => {
        await invoke("ask_close", { id: ask.id });
        message(`Declined. ${ask.name} got no access.`);
      }),
    );
    const row = document.createElement("div");
    row.className = "button-row";
    row.append(share, decline);
    item.append(who, words, row);
    list.append(item);
  }
}
function render(status: HomeStatus) {
  const hadStatus = current !== null;
  const oldPeer = current?.peer;
  const oldDevice = current?.selected_device;
  const wasJoining = !!current?.joining;
  const arrived = status.owner ? newAsks(current?.asks, status.asks) : [];
  if (hadStatus && arrived.length)
    message(`${arrived[0].name} asks for access. See Requests in Devices.`);
  current = status;
  renderAsks(status);
  activity.changed(status);
  advanced.render();
  visible("disconnected-banner", status.disconnected);
  visible("leave-retry", status.leaving);
  visible("leave-network-option", status.can_leave);
  visible("owner-leave-note", !status.can_leave && status.owner);
  text("toggle-network-label", status.disconnected ? "Reconnect" : "Disconnect");
  text("network-action-description", status.disconnected
    ? "Off until you reconnect, even after reopening the app"
    : status.owner ? "Pauses access for your other devices. Your setup stays saved."
      : "Pauses connections. Your network and shared items stay saved.");
  const next = primaryScreen(status);
  if (next === "workspace" && !status.leaving) resume(status);
  if (status.leaving) {
    show("leaving");
  } else if (next !== "welcome" || !["create-screen", "join-screen", "restore-screen"].includes(screen))
    show(next === "joining" ? "joining-screen" : next);
  if (status.joining) {
    // The code is shown large on its own, as on the owner's screen.
    const code = /Compare code (\d+)\./.exec(status.joining)?.[1];
    text("joining-progress", status.joining.replace(/\s*Compare code \d+\./, ""));
    text("joining-code", code ?? "");
    visible("joining-code", code !== undefined);
  }
  // A phone closes its network while off screen and reopens it on return.
  const reopening = phoneHosting && status.configured && !status.owner;
  text("home-network", reopening ? "Reopening…" : status.network || "Your private network");
  el("home-network").dataset.state = status.disconnected || reopening ? "off" : "on";
  visible("home-network", status.configured);
  setIcon("this-device-icon", status.owner ? "house" : /Android|iPhone|iPad/.test(navigator.userAgent) ? "smartphone" : "monitor-smartphone");
  text("this-device-name", localName());
  text(
    "this-device-detail",
    status.owner
      ? phoneHosting ? "Runs your network while Connect is open" : "Runs your network"
      : "This device",
  );
  text("settings-network", status.network || "Your network");
  text(
    "settings-owner",
    status.owner
      ? phoneHosting ? "Runs on this phone while Connect is open" : "Runs on this computer"
      : "Managed by your network computer",
  );
  renderConnection(status);
  visible("recovery-card", status.owner && status.configured);
  const saved = recoverySavedAt();
  visible("recovery-reminder", recoveryReminder(status.owner, status.configured, saved));
  text("recovery-detail", recoveryStatus(saved));
  visible("add-device-button", status.owner && status.devices.length < 32);
  // Hidden until this build can confirm administrator changes on the device.
  visible("host-admin-card",status.owner&&status.administration===true);
  visible("client-admin-card",!status.owner&&status.configured&&status.administration===true);
  clientAdministration.observeContext(JSON.stringify([status.activity_scope,status.devices.find(d=>d.authority_connection)?.id]),!status.owner&&status.configured);
  clientRequests.observeContext(JSON.stringify([status.activity_scope,status.devices.find(d=>d.authority_connection)?.id]),!status.owner&&status.configured);
  // Without listed folders, a device browses the selected device's one folder.
  const legacy = !status.spaces.length && !!status.peer && !status.owner;
  visible("browse-button", !status.disconnected && legacy);
  if (!busy) text("browse-button", "Refresh");
  renderShortcuts(status);
  renderSpaces(status);
  visible("paired-device", !!status.peer);
  text("peer-name", status.peer || "");
  renderDevices(status);
  renderUnfinished(status);
  if (oldDevice !== status.selected_device) {
    currentSpace = null;
    folderPath = [];
    input("file-search").value = "";
    page = null;
    files = [];
    el("file-list").replaceChildren();
    visible("remote-folder", false);
    visible("file-preview", false);
    visible("more-files", false);
  }
  text(
    "peer-state",
    status.ready
      ? "Ready to connect · identity checked on connection"
      : "Connection paused · keep both apps open",
  );

  visible("files-add-device", status.owner && !status.peer);
  text("files-description", status.disconnected ? "Reconnect to use your shared items." : "Files, apps and services across your devices.");
  text("files-empty-description", legacy ? "Refresh to see your shared files." : filesEmptyText(status));
  visible("approval-card", !!status.request);
  approval = status.request?.id || "";
  if (status.request) {
    text("approval-name", status.request.name);
    text("approval-code", status.request.code);
    visible("pair-card", false);
  }
  if (!busy && status.problem !== statusProblem) {
    const previousProblem = statusProblem;
    statusProblem = status.problem;
    if (status.problem) problem(status.problem);
    else if (previousProblem) problem("");
  }
  if (status.legacy) {
    message(
      "This device has an existing technical setup. Its identity has been preserved. Use Advanced tools in Settings to review it.",
    );
  }
  if (!oldPeer && status.peer) {
    if (!status.owner && !status.disconnected && !status.spaces.length && !busy) setTimeout(() => void browse(false), 0);
    // Only after pairing here, not when a known device reconnects at launch.
    if (hadStatus && (wasJoining || !el("pair-card").hidden)) message(`${status.peer} added.`);
    visible("pair-card", false);
    // A known device reconnecting at launch stays where the person left off.
    if (hadStatus) selectView("files");
  }
}
function renderConnection(status: HomeStatus) {
  // Advanced profiles keep their local-mode sessions and have no setting.
  const connection =
    status.configured && status.connection?.guided ? status.connection : null;
  visible("connection-card", !!connection);
  if (!connection) return;
  text("connection-summary", connectionSummary(connection));
  visible("connection-owner", connection.network_computer);
  // A private network already keeps every device on the local network.
  visible(
    "connection-device",
    !connection.network_computer && connection.network === "public_relays",
  );
  if (busy || connectionDirty) return;
  el<HTMLInputElement>("connection-public").checked = connection.network === "public_relays";
  el<HTMLInputElement>("connection-local").checked = connection.network === "local_network";
  el<HTMLInputElement>("connection-local-only").checked = connection.own === "local_network";
}
function renderDevices(status: HomeStatus) {
  const list = el("saved-devices");
  // Polling must not replace a focused button every two seconds.
  const stamp = JSON.stringify([status.owner, status.devices]);
  if (list.dataset.state === stamp) return;
  list.dataset.state = stamp;
  list.replaceChildren();
  visible(
    "devices-note",
    !status.owner && status.devices.some((device) => device.member),
  );
  visible("saved-devices-label", status.devices.length > 0);
  for (const device of status.devices) {
    const row = document.createElement("div");
    row.className = "list-row";
    const main = document.createElement("button");
    main.className = "row-main";
    const words = document.createElement("span");
    words.className = "row-text";
    const name = document.createElement("strong");
    name.textContent = device.name;
    const detail = document.createElement("span");
    detail.textContent = device.authority_connection
      ? "Runs your network"
      : device.member
        ? "On your network"
        : "On your network";
    words.append(name, detail);
    main.append(tile(device.authority_connection ? "house" : "monitor-smartphone"), words);
    main.setAttribute("aria-description", "View shared items");
    const view = async () => {
      if (!device.selected) await invoke("select_device", { id: device.id });
      resetLibrary();
      await refresh();
      selectView("files");
      el<HTMLSelectElement>("space-device").value = device.id;
      if (current) renderSpaces(current);
      message("");
    };
    main.addEventListener("click", () => void run(main, view));
    row.append(main);
    // Members come from the network computer, which decides who belongs:
    // there a device is removed from the network, elsewhere only forgotten.
    if (!device.authority_connection && !device.member) {
      row.append(menu(device.name, [
        { label: "View shared items", action: view },
        status.owner
          ? { label: "Remove from network", danger: true, action: async () => {
              if (!window.confirm(`Remove ${device.name} from your network? Within a minute it loses access everywhere: the folders it shares stop, and the others no longer include it. To join again, it needs a fresh setup of Connect.`)) return;
              await invoke("remove_device", { id: device.id });
              message(`${device.name} was removed from your network.`);
            } }
          : { label: "Forget", danger: true, action: async () => {
              if (!window.confirm(`Forget ${device.name} on this device? This stops its local connections. Network membership and folder policies must be revoked separately.`)) return;
              await invoke("forget_device", { id: device.id });
              message(`${device.name} forgotten on this device.`);
            } },
      ], false));
    } else row.append(icon("chevron-right", 20));
    list.append(row);
  }
}
async function refresh() {
  if (!isTauri() || polling) return;
  polling = true;
  try {
    render(await invoke<HomeStatus>("home_status"));
  } catch (error) {
    problem(String(error));
  } finally {
    polling = false;
  }
}
el("choose-create").addEventListener("click", () => show("create-screen"));

async function changeConnection(button: HTMLButtonElement) {
  const reconnect = !!current?.disconnected;
  if (!reconnect && current?.owner && !window.confirm(`Disconnect this ${phoneHosting ? "phone" : "computer"}? Your other devices will lose access until you reconnect it.`)) return;
  await run(button, async () => {
    await invoke(reconnect ? "reconnect_network" : "disconnect_network");
    message(reconnect ? "Reconnection enabled. Checking your network…" : "Disconnected. Tap Reconnect whenever you’re ready.");
  });
}
el("toggle-network").addEventListener("click", () => void changeConnection(el("toggle-network")));
el("reconnect-banner").addEventListener("click", () => void changeConnection(el("reconnect-banner")));

async function leaveNetwork(button: HTMLButtonElement) {
  if (!current?.can_leave) return;
  if (!current.leaving && !window.confirm("Leave this network on this device? Its saved identity and in-app downloads will be removed. Files you saved elsewhere and your other devices stay unchanged. To join again, get a new invitation. The network computer may still list this old device until its owner removes it.")) return;
  await run(button, async () => {
    await invoke("leave_network");
    currentSpace = null; page = null; files = []; folderPath = []; downloadId = "";
    input("join-link").value = "";
    input("file-search").value = "";
    el("file-list").replaceChildren();
    visible("file-preview", false); visible("remote-folder", false);
    visible("pair-card", false); visible("approval-card", false);
    for (const key of Object.keys(localStorage)) {
      if (key.startsWith("genesismesh.connect.peers.v1:")) localStorage.removeItem(key);
    }
    selectView("files");
    message("You’ve left the network on this device. Use a new invitation to join again.");
  });
}
el("leave-network").addEventListener("click", () => void leaveNetwork(el("leave-network")));
el("retry-leave-network").addEventListener("click", () => void leaveNetwork(el("retry-leave-network")));
el("choose-join").addEventListener("click", () => show("join-screen"));
el("choose-restore").addEventListener("click", () => show("restore-screen"));
el("restore-form").addEventListener("submit", (event) => {
  event.preventDefault();
  void run(
    el<HTMLButtonElement>("restore-form").querySelector("button[type=submit]")!,
    async () => {
      const savedAt = await invoke<string | null>("recovery_restore", { key: input("restore-key").value });
      if (savedAt) {
        input("restore-key").value = "";
        message(`${restoredMessage(savedAt)} Your devices reconnect when they next check in; share your items again from this device.`);
        selectView("devices");
      }
    },
  );
});
/** When this device last saved a recovery file, if it remembers. */
function recoverySavedAt(): string | null {
  try {
    return localStorage.getItem(RECOVERY_SAVED_KEY);
  } catch {
    return null;
  }
}
function saveRecovery(button: HTMLButtonElement) {
  void run(button, async () => {
    const key = await invoke<string | null>("recovery_create");
    if (!key) return;
    text("recovery-key", key);
    el<HTMLDialogElement>("recovery-dialog").showModal();
  });
}
el("create-recovery").addEventListener("click", () => saveRecovery(el<HTMLButtonElement>("create-recovery")));
el("recovery-reminder-save").addEventListener("click", () => saveRecovery(el<HTMLButtonElement>("recovery-reminder-save")));
el("recovery-offer-save").addEventListener("click", () => {
  el<HTMLDialogElement>("recovery-offer").close();
  saveRecovery(el<HTMLButtonElement>("recovery-reminder-save"));
});
el("recovery-offer-later").addEventListener("click", () => {
  el<HTMLDialogElement>("recovery-offer").close();
  message("You can save a recovery file any time from Devices or Settings.");
});
// The key is shown once, so only this button closes it.
el("recovery-dialog").addEventListener("cancel", (event) => event.preventDefault());
el("recovery-done").addEventListener("click", () => {
  text("recovery-key", "");
  try {
    localStorage.setItem(RECOVERY_SAVED_KEY, new Date().toISOString());
  } catch {
    // Without storage the reminder stays; the file itself was saved.
  }
  visible("recovery-reminder", false);
  text("recovery-detail", recoveryStatus(recoverySavedAt()));
  el<HTMLDialogElement>("recovery-dialog").close();
  message("Keep the recovery file and its key in separate places.");
});
el("choose-existing").addEventListener(
  "click",
  () =>
    void run(el<HTMLButtonElement>("choose-existing"), async () => {
      if (await invoke<boolean>("network_attach")) {
        message(
          "Existing network connected. Your authority must keep running on this computer.",
        );
        selectView("devices");
      }
    }),
);
for (const back of document.querySelectorAll("[data-back]"))
  back.addEventListener("click", () => show("welcome"));
for (const button of document.querySelectorAll<HTMLElement>("[data-view]"))
  button.addEventListener("click", () =>
    {
      const next = button.dataset.view || "files";
      selectView(next);
      if (next === "files" && current?.peer && !current.spaces.length && !page && !busy) void browse(false);
      // Devices that joined since the last refresh appear without waiting.
      if (next === "devices" && current?.configured)
        void invoke("check_network").then(refresh, () => undefined);
    },
  );
el("home-brand").addEventListener("click", (event) => {
  event.preventDefault();
  selectView("files");
});
el("create-form").addEventListener("submit", (event) => {
  event.preventDefault();
  void run(
    el<HTMLButtonElement>("create-form").querySelector("button[type=submit]")!,
    async () => {
      localStorage.setItem(
        "connect.friendly-name",
        input("computer-name").value.trim(),
      );
      await invoke("network_create", {
        name: input("create-name").value.trim(),
      });
      message(
        phoneHosting
          ? "Your network is ready. Add another device to share with it."
          : "Your network is ready. Add your phone to connect your devices.",
      );
      selectView("devices");
      // Recovery is offered while it is fresh in mind; Later keeps a reminder.
      el<HTMLDialogElement>("recovery-offer").showModal();
    },
  );
});
el("join-form").addEventListener("submit", (event) => {
  event.preventDefault();
  void run(
    el<HTMLFormElement>("join-form").querySelector("button[type=submit]")!,
    async () => {
      localStorage.setItem(
        "connect.friendly-name",
        input("join-name").value.trim(),
      );
      await invoke("pair_join", {
        link: input("join-link").value.trim(),
        name: input("join-name").value.trim(),
      });
    },
  );
});
async function addDevice(button: HTMLButtonElement) {
  await run(button, async () => {
    const result = await invoke<{ link: string; expires_at: number }>(
      "pair_begin",
      { name: localName() },
    );
    invitation = result.link;
    expiresAt = result.expires_at;
    el<HTMLImageElement>("pair-qr").src = await QRCode.toDataURL(invitation, {
      width: 320,
      margin: 3,
      errorCorrectionLevel: "M",
      color: { dark: "#101613", light: "#ffffff" },
    });
    visible("pair-card", true);
    // The invitation comes first on the page, clear of the top bar.
    window.scrollTo({ top: 0, behavior: "smooth" });
  });
}
for (const id of ["add-device-button", "files-add-device"])
  el(id).addEventListener(
    "click",
    () => void addDevice(el<HTMLButtonElement>(id)),
  );
el("share-invitation").addEventListener(
  "click",
  () =>
    void run(el<HTMLButtonElement>("share-invitation"), async () => {
      await invoke("share_invitation", { text: invitation });
    }),
);
el("copy-invitation").addEventListener(
  "click",
  () =>
    void run(el<HTMLButtonElement>("copy-invitation"), async () => {
      await navigator.clipboard.writeText(invitation);
      message(
        "Invitation copied. Share it only with the device you want to add.",
      );
    }),
);
el("hide-pair-card").addEventListener(
  "click",
  () =>
    void run(el<HTMLButtonElement>("hide-pair-card"), async () => {
      await invoke("pair_cancel");
      visible("pair-card", false);
      invitation = "";
      expiresAt = 0;
      message("Invitation closed. It can no longer be used.");
    }),
);
el("approve-device").addEventListener(
  "click",
  () =>
    void run(el<HTMLButtonElement>("approve-device"), async () => {
      const done = explainWait(null, finishingTitle(el("approval-name").textContent), finishingDetail);
      try {
        await invoke("pair_approve", { id: approval });
      } finally {
        done();
      }
      message("Device approved and securely paired.");
    }),
);
el("reject-device").addEventListener(
  "click",
  () =>
    void run(el<HTMLButtonElement>("reject-device"), async () => {
      await invoke("pair_reject", { id: approval });
      message(
        "Device was not allowed. Create a new invitation if you want to try again.",
      );
    }),
);
function renderShortcuts(status: HomeStatus) {
  const node = el("sharing-shortcuts");
  const choices = status.devices.length ? sharingChoices(status) : [];
  visible("sharing-shortcuts", !currentSpace && !page && choices.length > 0);
  const stamp = JSON.stringify([choices, status.disconnected]);
  if (node.dataset.state === stamp) return;
  node.dataset.state = stamp; node.replaceChildren();
  const shortcuts: Record<string, [string, string, IconName]> = {
    file: ["Document", "Share a document", "file-text"], media: ["Photos", "Share photos and videos", "image"],
    folder: ["Folder", "Share a folder", "folder-plus"], service: ["App", "Share an app or service", "app-window"],
    inbox: ["Receive", "Receive files on this device", "inbox"], send: ["Send", "Send files to a device", "send"],
  };
  for (const choice of choices) {
    const [label, hint, symbol] = shortcuts[choice.kind];
    const button = document.createElement("button"); button.className = "sharing-shortcut";
    button.dataset.shareKind = choice.kind; button.disabled = status.disconnected;
    button.setAttribute("aria-label", hint);
    const word = document.createElement("span"); word.textContent = label;
    button.append(tile(symbol), word); node.append(button);
  }
}
function resetLibrary() {
  currentSpace = null; page = null; files = []; folderPath = [];
  visible("remote-folder", false); visible("file-preview", false);
  input("space-search").value = ""; el<HTMLSelectElement>("space-device").value = "";
  libraryFilter = "all";
}
input("space-search").addEventListener("input", () => { if (current) renderSpaces(current); });
el("space-device").addEventListener("change", () => { if (current) renderSpaces(current); });
el("clear-library-filters").addEventListener("click", () => { resetLibrary(); if (current) render(current); });
for (const button of document.querySelectorAll<HTMLButtonElement>("[data-library-filter]")) {
  button.addEventListener("click", () => { libraryFilter = button.dataset.libraryFilter as LibraryFilter; if (current) renderSpaces(current); });
}
/** What an item is called on screen. */
function spaceTitle(space: HomeSpace) {
  return space.kind === "inbox" ? (space.own ? "Received files" : `Send to ${space.host}`) : space.name;
}
function renderSpaces(status: HomeStatus) {
  const list = el("space-list");
  visible("space-list", !currentSpace);
  visible("library-tools", !currentSpace);
  const select = el<HTMLSelectElement>("space-device");
  const hosts = new Map(status.devices.map(d => [d.id, d.name]));
  for (const space of status.spaces) hosts.set(space.host_id, space.own ? "This device" : space.host);
  const hostStamp = JSON.stringify([...hosts]);
  if (select.dataset.state !== hostStamp) {
    const value = select.value; select.replaceChildren(new Option("All devices", ""));
    for (const [id, name] of hosts) select.add(new Option(name, id));
    select.value = hosts.has(value) ? value : ""; select.dataset.state = hostStamp;
  }
  const filtered = visibleSpaces(status.spaces, input("space-search").value, libraryFilter, select.value);
  const filteredView = !!input("space-search").value || !!select.value || libraryFilter !== "all";
  text("library-count", `${filtered.length} shared ${filtered.length === 1 ? "item" : "items"}`);
  visible("library-no-matches", !currentSpace && !filtered.length && filteredView);
  text("library-empty-hint", input("space-search").value ? "Try another name or clear your filters." : libraryFilter === "mine" ? "Use a sharing shortcut above to share from this device." : "Nothing is shared in this view. On the other device, choose Share and select this device.");
  visible("files-empty", !currentSpace && !status.spaces.length && !filteredView && !page);
  for (const button of document.querySelectorAll<HTMLElement>("[data-library-filter]")) button.setAttribute("aria-pressed", String(button.dataset.libraryFilter === libraryFilter));
  // Search and the device filter help in a long list, the filters once there are a few.
  visible("library-search", status.spaces.length >= 8 || !!input("space-search").value || !!select.value);
  visible("library-filters", status.spaces.length >= 4 || libraryFilter !== "all");
  // Preserve keyboard focus during status polling.
  const stamp = JSON.stringify([filtered, status.disconnected]);
  if (list.dataset.state === stamp) return;
  list.dataset.state = stamp;
  list.replaceChildren();
  for (const space of filtered) list.append(spaceRow(space, status));
}
function spaceIcon(space: HomeSpace): IconName {
  if (isService(space)) return space.kind === "web" ? "app-window" : "terminal";
  if (space.kind === "inbox") return space.own ? "inbox" : "send";
  if (/\.(jpe?g|png|gif|webp|heic|mp4|mov)$/i.test(space.name)) return "image";
  return /\.\w{1,5}$/.test(space.name) ? "file-text" : "folder";
}
/** One shared item: a tap uses it, ⋯ manages what this device shares. */
function spaceRow(space: HomeSpace, status: HomeStatus) {
  const title = spaceTitle(space);
  const row = document.createElement("div");
  row.className = "list-row";
  row.setAttribute("role", "listitem");
  const main = document.createElement("button");
  main.className = "row-main";
  main.disabled = status.disconnected;
  const words = document.createElement("span");
  words.className = "row-text";
  const name = document.createElement("strong");
  name.textContent = title;
  const where = document.createElement("span");
  where.textContent = spaceSummary(space);
  words.append(name, where);
  if (space.duplicate) {
    const warning = document.createElement("span");
    warning.className = "row-warning";
    warning.textContent = "Shared twice. Check access on both, then stop the extra one.";
    words.append(warning);
  }
  main.append(tile(spaceIcon(space)), words);
  row.append(main);
  let use: () => Promise<void> = () => openSpace(space);
  let label = "";
  if (space.kind === "inbox" && !space.own) {
    use = () => sendTo(space);
    label = "Send";
  } else if (isService(space)) {
    use = space.own ? () => services.access(space) : () => services.open(space);
    if (!space.own) label = space.kind === "web" ? "Open" : "Connect";
  }
  main.addEventListener("click", () => void run(main, use));
  if (label) {
    const action = document.createElement("button");
    action.className = "tonal small";
    action.textContent = label;
    action.setAttribute("aria-label", space.kind === "inbox" ? `Send a file to ${space.host}` : `${label} ${title}`);
    action.disabled = status.disconnected;
    action.addEventListener("click", () => void run(action, use));
    row.append(action);
  } else if (!space.own) row.append(icon("chevron-right", 20));
  if (space.own) {
    const items: { label: string; danger?: boolean; action: () => Promise<void> }[] = [
      { label: "Manage access", action: () => services.access(space) },
    ];
    if (space.kind === "inbox" && status.can_share_folder)
      items.push({ label: "Show in folder", action: async () => { await invoke("show_received_folder", { space: space.id }); } });
    items.push(space.kind === "inbox"
      ? { label: "Stop receiving", danger: true, action: async () => {
          if (!window.confirm("Stop receiving files? Your devices can no longer send files here. Files already received stay in the folder.")) return;
          await invoke("stop_sharing", { id: space.id });
          message("This device no longer receives files.");
        } }
      : { label: "Stop sharing", danger: true, action: async () => {
          if (!window.confirm(isService(space) ? `Stop sharing ${space.name}? Its connections will close and other devices can no longer open it.` : `Stop sharing ${space.name}? Your other devices can no longer open it. Files they already saved stay on them.`)) return;
          const confirmed = await invoke<boolean>("stop_sharing", { id: space.id });
          message(
            confirmed
              ? `${space.name} is no longer shared.`
              : `${space.name} is no longer shared from this device. Your network computer will update its list when it can be reached.`,
          );
        } });
    row.append(menu(title, items, status.disconnected));
  }
  return row;
}
interface SendProgress {
  state: "checking" | "sending" | "complete" | "failed" | "canceled";
  sent: number; total: number; problem: string | null; saved_as: string | null; name: string;
}
let sendId = "";
async function sendTo(space: HomeSpace) {
  const id = await invoke<string | null>("send_file", { space: space.id });
  if (!id) return;
  sendId = id;
  visible("cancel-send", true);
  try {
    while (true) {
      const progress = await invoke<SendProgress>("send_status", { id });
      message(`${progress.name} to ${space.host}: ${sendSummary(progress)}`);
      if (progress.state === "complete" || progress.state === "canceled") return;
      if (progress.state === "failed") throw new Error(progress.problem || "Sending failed. Please try again.");
      await new Promise((resolve) => setTimeout(resolve, 300));
    }
  } finally {
    visible("cancel-send", false);
  }
}
el("cancel-send").addEventListener("click", () => {
  if (sendId) void invoke("cancel_send", { id: sendId }).catch((error) => problem(String(error)));
});
/** Remembers where the person is, so a relaunch returns there. */
function remember() {
  try {
    localStorage.setItem(PLACE_KEY, JSON.stringify(place(currentView as View, currentSpace?.id ?? null, folderPath)));
  } catch {
    // Without storage Connect simply starts at Shared.
  }
}
let resumed = false;
/** Once per launch, back to the view, Space and folder the person left. */
function resume(status: HomeStatus) {
  if (resumed) return;
  resumed = true;
  let saved: string | null = null;
  try {
    saved = localStorage.getItem(PLACE_KEY);
  } catch {
    return;
  }
  const to = resumeTo(readPlace(saved), status.spaces);
  if (!to) return;
  if (to.view !== currentView) selectView(to.view);
  const space = to.space ? status.spaces.find((s) => s.id === to.space) : undefined;
  if (!space || to.view !== "files" || space.kind === "inbox" && !space.own || isService(space)) return;
  // After this render; a failure keeps the Spaces list and says why.
  setTimeout(() => void run(el<HTMLButtonElement>("browse-button"), async () => {
    await openSpace(space);
    if (to.path.length) await loadFiles(false, to.path);
  }), 0);
}
async function openSpace(space: HomeSpace) {
  const previous = { currentSpace, folderPath, page, files };
  currentSpace = space;
  folderPath = [];
  page = null;
  files = [];
  input("file-search").value = "";
  try { await loadFiles(false); }
  catch (error) {
    ({ currentSpace, folderPath, page, files } = previous);
    throw error;
  }
}
el("all-spaces").addEventListener("click", () => {
  currentSpace = null;
  page = null;
  files = [];
  folderPath = [];
  remember();
  visible("remote-folder", false);
  visible("file-preview", false);
  if (current) render(current);
});
function renderFiles() {
  const list = el("file-list");
  list.replaceChildren();
  const shown = sortedFiles(filterFiles(files, input("file-search").value), el<HTMLSelectElement>("file-sort").value);
  text("file-count", `${shown.length} shown${page?.next ? " · Load more below" : ""}`);
  for (const file of shown) {
    const row = document.createElement("button");
    row.className = "file-row";
    row.setAttribute("role", "listitem");
    const symbol = icon(file.kind === "folder" ? "folder" : "file");
    symbol.classList.add("file-symbol");
    const name = document.createElement("span");
    name.textContent = file.name;
    const size = document.createElement("small");
    if (file.kind === "folder") size.append(icon("chevron-right", 20));
    else size.textContent = formatBytes(file.bytes);
    row.append(symbol, name, size);
    row.addEventListener("click", () => {
      if (file.kind === "folder") void run(row, () => loadFiles(false, [...folderPath, file.name]));
      else void open(file, row);
    });
    list.append(row);
  }
  if (!list.childElementCount) {
    const empty = document.createElement("p");
    empty.className = "home-muted";
    empty.textContent = files.length
      ? "No matching files."
      : currentSpace?.own && currentSpace.kind==="inbox" ? "No files received yet. On your other device, choose Send files and select this device." : "This folder is empty.";
    list.append(empty);
  }
}
function renderBreadcrumbs() {
  const navigation = el("folder-breadcrumbs");
  navigation.replaceChildren();
  const crumbs = folderCrumbs(folderPath, currentSpace ? spaceTitle(currentSpace) : undefined);
  crumbs.forEach((crumb, index) => {
    if (index) {const separator = document.createElement("span"); separator.textContent="/"; separator.setAttribute("aria-hidden","true"); navigation.append(separator);}
    const button = document.createElement("button");
    button.textContent = crumb.name;
    if (index === crumbs.length - 1) button.setAttribute("aria-current", "location");
    button.addEventListener("click", () => void run(button, () => loadFiles(false, crumb.directory)));
    navigation.append(button);
  });
}
/**
 * Explains a wait for another device after 2.5 seconds: who it waits for, for
 * how long, and, with an id, a Cancel that stops waiting. Returns the cleanup.
 */
function explainWait(id: string | null, title: string, detail: (ms: number) => string): () => void {
  const started = Date.now();
  const banner = el("wait-banner");
  const update = () => {
    text("wait-title", title);
    text("wait-detail", detail(Date.now() - started));
  };
  let ticking: ReturnType<typeof setInterval> | undefined;
  const showing = setTimeout(() => {
    update();
    banner.hidden = false;
    ticking = setInterval(update, 1000);
  }, EXPLAIN_AFTER_MS);
  const cancel = el<HTMLButtonElement>("wait-cancel");
  cancel.disabled = false;
  cancel.hidden = !id;
  cancel.onclick = () => {
    cancel.disabled = true;
    text("wait-detail", "Stopping…");
    void invoke("cancel_wait", { id });
  };
  return () => {
    clearTimeout(showing);
    clearInterval(ticking);
    banner.hidden = true;
    cancel.onclick = null;
  };
}
async function loadFiles(more: boolean, directory = folderPath) {
  const remote = !(currentSpace?.own && !isService(currentSpace));
  const wait = remote ? crypto.randomUUID() : null;
  const done = wait ? explainWait(wait, waitTitle(currentSpace?.host ?? current?.peer), waitDetail) : () => {};
  let result: FilePage;
  try {
    result = await invoke<FilePage>(remote ? "browse_files" : "browse_received", {
      after: more ? page?.next : null,
      directory,
      space: currentSpace?.id ?? null,
      ...(wait ? { wait } : {}),
    });
  } catch (error) {
    if (!stoppedWaiting(error)) throw error;
    message(STOPPED);
    return;
  } finally {
    done();
  }
  if (JSON.stringify(result.directory) !== JSON.stringify(folderPath)) input("file-search").value = "";
  folderPath = result.directory;
  page = result;
  remember();
  renderBreadcrumbs();
  files = more ? [...files, ...result.files] : result.files;
  renderFiles();
  visible("remote-folder", true);
  visible("sharing-shortcuts", false);
  visible("files-empty", false);
  visible("more-files", !!page.next);
  visible("file-preview", false);
  text(
    "remote-folder-title",
    currentSpace ? spaceTitle(currentSpace) : `From ${current?.peer || "your device"}`,
  );
  text("remote-folder-subtitle", currentSpace ? spaceSummary(currentSpace) : "");
  // Search, sort and the path appear only where they help.
  const many = files.length > 20 || !!page.next;
  visible("file-search", many);
  el("file-sort").parentElement!.hidden = !many;
  visible("folder-breadcrumbs", folderPath.length > 0);
  visible("all-spaces", !!currentSpace);
  visible("space-list", false);
  visible("library-tools", false);
  message("");
}
async function browse(more: boolean) {
  await run(el<HTMLButtonElement>(more ? "more-files" : "browse-button"), () => loadFiles(more));
}
el("browse-button").addEventListener("click", () => {
  if (currentSpace || page || current?.peer && !current.spaces.length && !current.owner) void browse(false);
  else void run(el<HTMLButtonElement>("browse-button"), async () => { await invoke("check_network"); });
});
el("more-files").addEventListener("click", () => void browse(true));
input("file-search").addEventListener("input", renderFiles);
el("file-sort").addEventListener("change", renderFiles);
interface DownloadProgress {
  name: string; total: number; received: number;
  state: "downloading" | "verifying" | "complete" | "failed" | "canceled";
  problem: string | null; text: string | null; can_open: boolean;
}
/** Downloads that stopped: each continues where it stopped, or goes. */
function renderUnfinished(status: HomeStatus) {
  const list = el("unfinished-list");
  const stamp = JSON.stringify(status.unfinished);
  if (list.dataset.state === stamp) return;
  list.dataset.state = stamp;
  list.replaceChildren();
  visible("unfinished-downloads", status.unfinished.length > 0);
  for (const item of status.unfinished) {
    const row = document.createElement("div");
    row.className = "device-row";
    row.setAttribute("role", "listitem");
    const details = document.createElement("div");
    const name = document.createElement("h3");
    name.textContent = item.name;
    const detail = document.createElement("p");
    detail.className = "home-muted";
    detail.textContent = `${formatBytes(item.received)} of ${formatBytes(item.total)}`;
    details.append(name, detail);
    const resume = document.createElement("button");
    resume.textContent = "Continue";
    resume.addEventListener("click", () =>
      void download(item.name, resume, () => invoke<string>("resume_download", { id: item.id })),
    );
    const drop = document.createElement("button");
    drop.textContent = "Discard";
    drop.className = "secondary";
    drop.addEventListener("click", () => {
      if (busy) {
        message("Wait for the current download or action to finish.");
        return;
      }
      void run(drop, async () => {
        await invoke("discard_download", { id: item.id });
        message(`${item.name} discarded.`);
      });
    });
    row.append(details, resume, drop);
    list.append(row);
  }
}
async function open(file: FileEntry, button: HTMLButtonElement) {
  if (!page) return;
  const collectionId = page.collection_id;
  if (currentSpace?.own && !isService(currentSpace)) {
    await run(button, () => invoke("export_received", { collectionId, directory: folderPath, name: file.name, version: file.version, open: true }));
    return;
  }
  const directory = folderPath;
  // A file left unfinished continues where it stopped.
  await download(file.name, button, () =>
    invoke<string>("download_file", {
      collectionId, directory, name: file.name, version: file.version, size: file.bytes,
    }),
  );
}
async function download(fileName: string, button: HTMLButtonElement, begin: () => Promise<string>) {
  if (busy) {
    message("Wait for the current download or action to finish.");
    return;
  }
  await run(button, async () => {
    downloadId = "";
    pendingStop = null;
    text("preview-name", fileName);
    text("preview-detail", "Preparing download…");
    text("preview-content", "");
    visible("preview-content", false);
    visible("open-download", false);
    visible("save-download", false);
    visible("download-progress", true);
    visible("cancel-download", true);
    visible("file-preview", true);
    visible("remote-folder", false);
    downloadId = await begin();
    // Stopped while it was being prepared: stop it now, then follow it
    // until it has stopped, so the next one finds it listed.
    if (pendingStop) await invoke("cancel_download", { id: downloadId, keep: pendingStop === "keep" });
    try {
      while (true) {
        const progress = await invoke<DownloadProgress>("download_status", { id: downloadId });
        (el("download-progress") as HTMLProgressElement).value = progress.total ? progress.received / progress.total * 100 : 100;
        text("preview-detail", progress.state === "verifying" ? "Checking file…" : `${formatBytes(progress.received)} of ${formatBytes(progress.total)}`);
        if (progress.state === "complete") {
          text("preview-detail", `${formatBytes(progress.total)} · Ready`);
          text("preview-content", progress.text || "");
          visible("preview-content", progress.text !== null);
          visible("open-download", progress.can_open);
          visible("save-download", true);
          break;
        }
        if (progress.state === "canceled") {text("preview-detail", "Download stopped"); break;}
        if (progress.state === "failed") throw new Error(progress.problem || "Download failed. Please try again.");
        await new Promise((resolve) => setTimeout(resolve, 300));
      }
    } finally {
      visible("cancel-download", false);
      visible("download-progress", false);
    }
  });
}
el("cancel-download").addEventListener("click", () => {
  if (busy && downloadId) void invoke("cancel_download", { id: downloadId }).catch((error) => problem(String(error)));
  else if (busy) pendingStop = "discard";
});
el("open-download").addEventListener("click", () => void run(el<HTMLButtonElement>("open-download"), async () => {
  await invoke("open_download", { id: downloadId });
}));
el("save-download").addEventListener("click", () => void run(el<HTMLButtonElement>("save-download"), async () => {
  if (await invoke<boolean>("save_download", { id: downloadId })) message("Your file is ready to save.");
}));
// Going back keeps what arrived, to continue later; Cancel discards it.
el("close-preview").addEventListener("click", () => {
  if (busy && downloadId) void invoke("cancel_download", { id: downloadId, keep: true }).catch(() => {});
  else if (busy) pendingStop = "keep";
  visible("file-preview", false);
  visible("remote-folder", !!page);
});
el("check-connection-button").addEventListener(
  "click",
  () =>
    void run(el<HTMLButtonElement>("check-connection-button"), async () => {
      await invoke("check_connection");
      text("peer-state", "Connected · device identity verified");
      message("Secure connection succeeded.");
    }),
);
// Save appears once a choice changes, and goes when it is saved or dropped.
function connectionChanged(dirty: boolean) {
  connectionDirty = dirty;
  visible("save-connection", dirty);
  visible("save-device-connection", dirty);
}
for (const id of ["connection-public", "connection-local", "connection-local-only"])
  el(id).addEventListener("change", () => connectionChanged(true));
el("save-connection").addEventListener(
  "click",
  () =>
    void run(el<HTMLButtonElement>("save-connection"), async () => {
      const setting = el<HTMLInputElement>("connection-local").checked
        ? "local_network"
        : "public_relays";
      try {
        await invoke("set_network_connection", { setting });
      } finally {
        connectionChanged(false);
      }
      message(
        setting === "local_network"
          ? "Your devices now connect only on this local network."
          : "Your devices can now reach each other from anywhere.",
      );
    }),
);
el("save-device-connection").addEventListener(
  "click",
  () =>
    void run(el<HTMLButtonElement>("save-device-connection"), async () => {
      const enabled = el<HTMLInputElement>("connection-local-only").checked;
      try {
        await invoke("set_device_local_only", { enabled });
      } finally {
        connectionChanged(false);
      }
      message(
        enabled
          ? "This device now connects only on the local network."
          : "This device follows your network’s connection setting.",
      );
    }),
);
// Save is offered only for a new, valid name.
function nameChanged() {
  const name = input("friendly-name").value.trim();
  el<HTMLButtonElement>("save-name").disabled = !name || name.length > 64 || name === localName();
}
input("friendly-name").addEventListener("input", nameChanged);
el("save-name").addEventListener("click", () => {
  const name = input("friendly-name").value.trim();
  if (!name || name.length > 64) return;
  localStorage.setItem("connect.friendly-name", name);
  text("this-device-name", name);
  nameChanged();
  message("Name saved on this device.");
});
// The advanced tools are one step from the everyday screens: the back bar,
// the logo and a phone's back gesture all return.
let advancedEntry = false;
function showAdvanced(open: boolean) {
  if (open === !el("advanced-shell").hidden) return;
  visible("everyday", !open);
  visible("advanced-shell", open);
  if(open){el<HTMLDetailsElement>("expert-tools").open=false;el<HTMLDetailsElement>("advanced-error-details").open=false;showPage("guide");}
  window.scrollTo(0, 0);
  el(open ? "close-advanced" : "open-advanced").focus({ preventScroll: true });
  if (!open) void refresh();
}
// Closed at once; the history entry follows, so a second tap does nothing.
function leaveAdvanced() {
  const entry = advancedEntry;
  advancedEntry = false;
  showAdvanced(false);
  if (entry) history.back();
}
el("open-advanced").addEventListener("click", () => {
  showAdvanced(true);
  history.pushState({ advanced: true }, "");
  advancedEntry = true;
});
el("close-advanced").addEventListener("click", leaveAdvanced);
document
  .querySelector<HTMLAnchorElement>("#advanced-shell .brand")
  ?.addEventListener("click", (event) => {
    event.preventDefault();
    leaveAdvanced();
  });
// The history entry decides, also after a reload or going forward again.
window.addEventListener("popstate", (event) => {
  advancedEntry = !!event.state?.advanced;
  showAdvanced(advancedEntry);
});
if (history.state?.advanced) {
  advancedEntry = true;
  showAdvanced(true);
}
async function acceptLink(urls: string[] | null) {
  const link = urls?.find((url) => url.startsWith("genesismesh://join/"));
  if (!link) return;
  leaveAdvanced();
  input("join-link").value = link;
  show("join-screen");
  message("Invitation received. Name this device and ask to join.");
}
let phoneHosting = false;
/** This phone runs the network itself: say so where setup says "computer". */
function usePhoneSetupWording() {
  phoneHosting = true;
  visible("share-invitation", true);
  el("choose-create").querySelector("strong")!.textContent =
    "Start on this phone";
  el("choose-create").querySelector("span:not(.choice-symbol)")!.textContent =
    "Your phone runs your network while Connect is open.";
  const where = availability("phone");
  text("create-where", where.where);
  text("create-always-on", where.alwaysOn);
  text("create-protect", "It asks for your screen lock once, to protect the network's main key.");
  visible("create-protect", true);
  for (const id of ["recovery-reminder-text", "recovery-offer-text"])
    text(id, el(id).textContent!.replace(/this device/g, "this phone"));
  document.querySelector('label[for="computer-name"]')!.textContent =
    "This phone's name";
  if (!localStorage.getItem("connect.friendly-name"))
    input("computer-name").value = "My phone";
  text("owner-leave-note", "This phone runs your network. Leaving here would affect your other devices; use Disconnect to pause it.");
}
if (isTauri()) {
  void onOpenUrl((urls) => void acceptLink(urls));
  void getCurrent()
    .then(acceptLink)
    .catch(() => {});
  void invoke<{ runtime_available: boolean; phone: boolean }>(
    "network_status",
  ).then((status) => {
    el<HTMLButtonElement>("choose-create").disabled = !status.runtime_available;
    visible("choose-create", status.runtime_available);
    visible("create-unavailable", !status.runtime_available);
    // An existing desktop network is opened on its computer.
    visible("choose-existing", status.runtime_available && !status.phone);
    visible("choose-restore", status.runtime_available);
    if (status.phone) usePhoneSetupWording();
  });
  void refresh();
  setInterval(() => {
    if (!document.hidden) void refresh();
    if (expiresAt) {
      const left = Math.max(0, expiresAt - Math.floor(Date.now() / 1000));
      text(
        "pair-expiry",
        left
          ? `Invitation expires in ${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")}`
          : "Invitation expired. Close it and create a new one.",
      );
    }
  }, 2000);
} else {
  show("welcome");
  message("Open the installed Connect app to create or join a network.");
  for (const id of ["choose-create", "choose-join"])
    el<HTMLButtonElement>(id).disabled = true;
}

const services = setupServices(() => current, refresh, message);
const hostAdministration=setupHostAdministration();
const clientAdministration=setupClientAdministration();
const clientRequests=setupClientRequests();
const activity = setupActivity(()=>current,()=>currentView==="activity",refresh,message,services.access);
const sharing = setupSharing(() => current, refresh, message, sendTo);

const advanced = setupAdvanced(()=>current,refresh,(view,anchor)=>{
  leaveAdvanced();selectView(view);
  requestAnimationFrame(()=>{
    const target=anchor?el(anchor):el(`view-${view}`);
    if(!target.closest("[hidden]")){
      target.scrollIntoView({block:"start"});const heading=target.querySelector<HTMLElement>("h1,h2");
      if(heading){heading.tabIndex=-1;heading.focus({preventScroll:true});}
    }else{
      const heading=[...document.querySelectorAll<HTMLElement>("#everyday h1,#everyday h2")].find(h=>!h.closest("[hidden]"));
      if(heading){heading.tabIndex=-1;heading.focus({preventScroll:true});}
    }
  });
});
