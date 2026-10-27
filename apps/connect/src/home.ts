import { invoke, isTauri } from "@tauri-apps/api/core";
import { getCurrent, onOpenUrl } from "@tauri-apps/plugin-deep-link";
import QRCode from "qrcode";
import { el, input } from "./ui";
import {
  primaryScreen,
  filterFiles,
  formatBytes,
  folderCrumbs,
  friendlyProblem,
  connectionSummary,
  spaceSummary,
  sendSummary,
  filesEmptyText,
  type HomeSpace,
  type HomeStatus,
  type FilePage,
  type FileEntry,
} from "./home-state";

let current: HomeStatus | null = null;
let statusProblem: string | null = null;
let screen = "welcome",
  busy = false,
  polling = false;
let invitation = "",
  expiresAt = 0,
  approval = "";
let downloadId = "";
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
    "welcome",
    "create-screen",
    "join-screen",
    "restore-screen",
    "joining-screen",
    "workspace",
  ])
    visible(name, name === next);
}
function selectView(next: string) {
  // An unsaved connection choice is dropped when leaving Settings.
  if (next !== "settings") connectionDirty = false;
  for (const name of ["files", "devices", "settings"])
    visible(`view-${name}`, name === next);
  for (const button of document.querySelectorAll<HTMLElement>("[data-view]"))
    button.setAttribute("aria-pressed", String(button.dataset.view === next));
}
async function run(button: HTMLButtonElement, action: () => Promise<void>) {
  if (busy) return;
  busy = true;
  button.disabled = true;
  const label = button.textContent;
  button.textContent = "Please wait…";
  problem("");
  try {
    await action();
    await refresh();
  } catch (error) {
    problem(String(error));
  } finally {
    busy = false;
    button.disabled = false;
    button.textContent = label;
  }
}
function render(status: HomeStatus) {
  const hadStatus = current !== null;
  const oldPeer = current?.peer;
  const oldDevice = current?.selected_device;
  current = status;
  const next = primaryScreen(status);
  if (next !== "welcome" || !["create-screen", "join-screen", "restore-screen"].includes(screen))
    show(next === "joining" ? "joining-screen" : next);
  if (status.joining) text("joining-progress", status.joining);
  text("home-network", status.network || "Your private network");
  text("this-device-name", localName());
  text(
    "this-device-detail",
    status.owner
      ? "Network computer"
      : "This device",
  );
  text("settings-network", status.network || "Your network");
  text(
    "settings-owner",
    status.owner
      ? "Managed on this computer"
      : "Managed by your network computer",
  );
  renderConnection(status);
  visible("recovery-card", status.owner && status.configured);
  visible("add-device-button", status.owner && status.devices.length < 32);
  visible("share-button", status.can_share && status.devices.length > 0);
  visible(
    "receive-button",
    status.can_share && status.devices.length > 0 && !status.spaces.some((s) => s.own && s.kind === "inbox"),
  );
  // Without listed folders, a device browses the selected device's one folder.
  const legacy = !status.spaces.length && !!status.peer && !status.owner;
  visible("browse-button", !!currentSpace || legacy);
  if (!busy) text("browse-button", currentSpace || page ? "Refresh" : `Files on ${status.peer || "another device"}`);
  renderSpaces(status);
  visible("paired-device", !!status.peer);
  text("peer-name", status.peer || "");
  renderDevices(status);
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
  visible("files-empty", !status.spaces.length && !page);
  visible("files-add-device", status.owner && !status.peer);
  text("files-description", "Shared folders on your network");
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
    if (!status.owner && !status.spaces.length && !busy) setTimeout(() => void browse(false), 0);
    if (hadStatus) message(`${status.peer} added.`);
    visible("pair-card", false);
    selectView("files");
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
  const stamp = JSON.stringify(status.devices);
  if (list.dataset.state === stamp) return;
  list.dataset.state = stamp;
  list.replaceChildren();
  for (const device of status.devices) {
    const row = document.createElement("section");
    row.className = "home-card device-row";
    const details = document.createElement("div");
    const name = document.createElement("h2");
    name.textContent = device.name;
    const detail = document.createElement("p");
    detail.textContent = device.authority_connection
      ? "Network computer"
      : device.member
        ? "On your network"
        : "Your device";
    details.append(name, detail);
    const choose = document.createElement("button");
    choose.textContent = "Open files";
    choose.className = "secondary";
    choose.addEventListener("click", () => void run(choose, async () => {
      if (!device.selected) await invoke("select_device", { id: device.id });
      currentSpace = null;
      await refresh();
      selectView("files");
      await loadFiles(false);
      message("");
    }));
    row.append(details, choose);
    // Members come from the network computer, which decides who belongs.
    if (!device.authority_connection && !device.member) {
      const forget = document.createElement("button");
      forget.textContent = "Forget";
      forget.className = "secondary";
      forget.addEventListener("click", () => void run(forget, async () => {
        if (!window.confirm(`Forget ${device.name} on this device? This stops its local connections. Network membership and folder policies must be revoked separately.`)) return;
        await invoke("forget_device", { id: device.id });
        message(`${device.name} forgotten on this device.`);
      }));
      const options = document.createElement("details");
      options.className = "device-options";
      const summary = document.createElement("summary");
      summary.textContent = "More";
      summary.setAttribute("aria-label", `More options for ${device.name}`);
      options.append(summary, forget);
      row.append(options);
    }
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
el("choose-join").addEventListener("click", () => show("join-screen"));
el("choose-restore").addEventListener("click", () => show("restore-screen"));
el("restore-form").addEventListener("submit", (event) => {
  event.preventDefault();
  void run(
    el<HTMLButtonElement>("restore-form").querySelector("button[type=submit]")!,
    async () => {
      if (await invoke<boolean>("recovery_restore", { key: input("restore-key").value })) {
        input("restore-key").value = "";
        message(
          "Your network is back. Your devices reconnect when they next check in. Share your folders again on this computer.",
        );
        selectView("devices");
      }
    },
  );
});
el("create-recovery").addEventListener(
  "click",
  () =>
    void run(el<HTMLButtonElement>("create-recovery"), async () => {
      const key = await invoke<string | null>("recovery_create");
      if (!key) return;
      text("recovery-key", key);
      visible("recovery-key-panel", true);
    }),
);
el("recovery-done").addEventListener("click", () => {
  text("recovery-key", "");
  visible("recovery-key-panel", false);
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
      if (next === "files" && current?.peer && !page && !busy) void browse(false);
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
      message("Your network is ready. Add your phone to connect your devices.");
      selectView("devices");
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
    el("pair-card").scrollIntoView({ behavior: "smooth", block: "start" });
  });
}
for (const id of ["add-device-button", "files-add-device"])
  el(id).addEventListener(
    "click",
    () => void addDevice(el<HTMLButtonElement>(id)),
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
      await invoke("pair_approve", { id: approval });
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
el("share-button").addEventListener(
  "click",
  () =>
    void run(el<HTMLButtonElement>("share-button"), async () => {
      if (await invoke<boolean>("share_folder"))
        message("Folder shared with your other devices. They can browse it now.");
    }),
);
function renderSpaces(status: HomeStatus) {
  const list = el("space-list");
  visible("space-list", !currentSpace);
  // Polling must not replace a focused button every two seconds.
  const stamp = JSON.stringify(status.spaces);
  if (list.dataset.state === stamp) return;
  list.dataset.state = stamp;
  list.replaceChildren();
  for (const space of status.spaces) {
    const row = document.createElement("section");
    row.className = "home-card space-row";
    row.setAttribute("role", "listitem");
    const details = document.createElement("div");
    const name = document.createElement("h2");
    name.textContent = space.name;
    const where = document.createElement("p");
    where.textContent = spaceSummary(space);
    details.append(name, where);
    const action = document.createElement("button");
    action.className = "secondary";
    if (space.own && space.kind === "inbox") {
      action.textContent = "Stop receiving";
      action.setAttribute("aria-label", "Stop receiving files");
      action.addEventListener("click", () => void run(action, async () => {
        if (!window.confirm("Stop receiving files? Your devices can no longer send files here. Files already received stay in the folder.")) return;
        await invoke("stop_sharing", { id: space.id });
        message("This device no longer receives files.");
      }));
    } else if (space.kind === "inbox") {
      action.textContent = "Send a file";
      action.setAttribute("aria-label", `Send a file to ${space.host}`);
      action.addEventListener("click", () => void run(action, () => sendTo(space)));
    } else if (space.own) {
      action.textContent = "Stop sharing";
      action.setAttribute("aria-label", `Stop sharing ${space.name}`);
      action.addEventListener("click", () => void run(action, async () => {
        if (!window.confirm(`Stop sharing ${space.name}? Your other devices can no longer open it. Files they already saved stay on them.`)) return;
        const confirmed = await invoke<boolean>("stop_sharing", { id: space.id });
        message(
          confirmed
            ? `${space.name} is no longer shared.`
            : `${space.name} is no longer shared from this device. Your network computer will update its list when it can be reached.`,
        );
      }));
    } else {
      action.textContent = "Open";
      action.setAttribute("aria-label", `Open ${space.name} on ${space.host}`);
      action.addEventListener("click", () => void run(action, () => openSpace(space)));
    }
    row.append(details, action);
    list.append(row);
  }
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
el("receive-button").addEventListener(
  "click",
  () =>
    void run(el<HTMLButtonElement>("receive-button"), async () => {
      if (await invoke<boolean>("receive_files"))
        message("Your other devices can now send files to this computer.");
    }),
);
async function openSpace(space: HomeSpace) {
  currentSpace = space;
  folderPath = [];
  page = null;
  files = [];
  input("file-search").value = "";
  await loadFiles(false);
}
el("all-spaces").addEventListener("click", () => {
  currentSpace = null;
  page = null;
  files = [];
  visible("remote-folder", false);
  visible("file-preview", false);
  if (current) render(current);
});
function renderFiles() {
  const list = el("file-list");
  list.replaceChildren();
  for (const file of filterFiles(files, input("file-search").value)) {
    const row = document.createElement("button");
    row.className = "file-row";
    row.setAttribute("role", "listitem");
    const icon = document.createElement("span");
    icon.className = "file-symbol";
    icon.textContent = file.kind === "folder" ? "📁" : "▤";
    icon.setAttribute("aria-hidden", "true");
    const name = document.createElement("span");
    name.textContent = file.name;
    const size = document.createElement("small");
    size.textContent = file.kind === "folder" ? "Folder  ›" : formatBytes(file.bytes);
    row.append(icon, name, size);
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
      : "This folder is empty.";
    list.append(empty);
  }
}
function renderBreadcrumbs() {
  const navigation = el("folder-breadcrumbs");
  navigation.replaceChildren();
  const crumbs = folderCrumbs(folderPath);
  crumbs.forEach((crumb, index) => {
    if (index) {const separator = document.createElement("span"); separator.textContent="/"; separator.setAttribute("aria-hidden","true"); navigation.append(separator);}
    const button = document.createElement("button");
    button.textContent = crumb.name;
    if (index === crumbs.length - 1) button.setAttribute("aria-current", "location");
    button.addEventListener("click", () => void run(button, () => loadFiles(false, crumb.directory)));
    navigation.append(button);
  });
}
async function loadFiles(more: boolean, directory = folderPath) {
  const result = await invoke<FilePage>("browse_files", {
    after: more ? page?.next : null,
    directory,
    space: currentSpace?.id ?? null,
  });
  if (JSON.stringify(result.directory) !== JSON.stringify(folderPath)) input("file-search").value = "";
  folderPath = result.directory;
  page = result;
  renderBreadcrumbs();
  files = more ? [...files, ...result.files] : result.files;
  renderFiles();
  visible("remote-folder", true);
  visible("files-empty", false);
  visible("more-files", !!page.next);
  visible("file-preview", false);
  text(
    "remote-folder-title",
    currentSpace ? `${currentSpace.name} · ${spaceSummary(currentSpace)}` : `From ${current?.peer || "your computer"}`,
  );
  visible("all-spaces", !!currentSpace);
  visible("space-list", false);
  message("");
}
async function browse(more: boolean) {
  await run(el<HTMLButtonElement>(more ? "more-files" : "browse-button"), () => loadFiles(more));
}
el("browse-button").addEventListener("click", () => void browse(false));
el("more-files").addEventListener("click", () => void browse(true));
input("file-search").addEventListener("input", renderFiles);
interface DownloadProgress {
  name: string; total: number; received: number;
  state: "downloading" | "verifying" | "complete" | "failed" | "canceled";
  problem: string | null; text: string | null; can_open: boolean;
}
async function open(file: FileEntry, button: HTMLButtonElement) {
  await run(button, async () => {
    if (!page) return;
    text("preview-name", file.name);
    text("preview-detail", "Preparing download…");
    text("preview-content", "");
    visible("preview-content", false);
    visible("open-download", false);
    visible("save-download", false);
    visible("download-progress", true);
    visible("cancel-download", true);
    visible("file-preview", true);
    visible("remote-folder", false);
    downloadId = await invoke<string>("download_file", {
      collectionId: page.collection_id, directory: folderPath, name: file.name, version: file.version, size: file.bytes,
    });
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
        if (progress.state === "canceled") {text("preview-detail", "Download canceled"); break;}
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
  if (downloadId) void invoke("cancel_download", { id: downloadId }).catch((error) => problem(String(error)));
});
el("open-download").addEventListener("click", () => void run(el<HTMLButtonElement>("open-download"), async () => {
  await invoke("open_download", { id: downloadId });
}));
el("save-download").addEventListener("click", () => void run(el<HTMLButtonElement>("save-download"), async () => {
  if (await invoke<boolean>("save_download", { id: downloadId })) message("Your file is ready to save.");
}));
el("close-preview").addEventListener("click", () => {
  if (busy && downloadId) void invoke("cancel_download", { id: downloadId }).catch(() => {});
  visible("file-preview", false);
  visible("remote-folder", true);
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
for (const id of ["connection-public", "connection-local", "connection-local-only"])
  el(id).addEventListener("change", () => {
    connectionDirty = true;
  });
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
        connectionDirty = false;
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
        connectionDirty = false;
      }
      message(
        enabled
          ? "This device now connects only on the local network."
          : "This device follows your network’s connection setting.",
      );
    }),
);
el("save-name").addEventListener("click", () => {
  const name = input("friendly-name").value.trim();
  if (!name || name.length > 64) return;
  localStorage.setItem("connect.friendly-name", name);
  text("this-device-name", name);
  message("Name saved on this device.");
});
el("open-advanced").addEventListener("click", () => {
  visible("everyday", false);
  visible("advanced-shell", true);
});
el("close-advanced").addEventListener("click", () => {
  visible("advanced-shell", false);
  visible("everyday", true);
  void refresh();
});
async function acceptLink(urls: string[] | null) {
  const link = urls?.find((url) => url.startsWith("genesismesh://join/"));
  if (!link) return;
  input("join-link").value = link;
  show("join-screen");
  message("Invitation received. Name this device and ask to join.");
}
if (isTauri()) {
  void onOpenUrl((urls) => void acceptLink(urls));
  void getCurrent()
    .then(acceptLink)
    .catch(() => {});
  void invoke<{ runtime_available: boolean }>("network_status").then(
    (status) => {
      el<HTMLButtonElement>("choose-create").disabled =
        !status.runtime_available;
      visible("create-unavailable", !status.runtime_available);
      visible("choose-existing", status.runtime_available);
      visible("choose-restore", status.runtime_available);
    },
  );
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
