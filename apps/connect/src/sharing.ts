import { invoke } from "@tauri-apps/api/core";
import { el, input } from "./ui";
import { friendlyProblem, type HomeStatus, type HomeSpace } from "./home-state";
import { sharingChoices, sharingDevices, type ShareKind } from "./sharing-state";
export function setupSharing(getStatus: () => HomeStatus | null, refresh: () => Promise<void>, message: (s: string) => void, send: (space: HomeSpace) => Promise<void>) {
  const dialog = el<HTMLDialogElement>("share-dialog"), confirm = el<HTMLButtonElement>("share-confirm");
  let submitting = false, selected: ShareKind = "file";
  const failure = (s: string) => { el("share-problem").textContent = s; el("share-problem").hidden = !s; };
  function choose(kind: ShareKind) {
    selected = kind; failure("");
    const status = getStatus(); if (!status) return;
    el("share-description").textContent = (sharingChoices(status).find(c => c.kind === kind)?.description || "") + " Keep Connect open while sharing or receiving.";
    el("share-recipients").hidden = kind === "send";
    el("share-inbox").hidden = el("share-inbox-label").hidden = kind !== "send";
    el("share-service-fields").hidden = kind !== "service";
    for (const field of el("share-service-fields").querySelectorAll<HTMLInputElement | HTMLSelectElement>("input,select")) field.disabled = kind !== "service";
    confirm.textContent = ({ service: "Share service", file: "Choose file and share", media: "Choose photo or video", folder: "Choose folder and share", inbox: "Start receiving", send: "Choose file and send" })[kind];
  }
  function open(kind?: ShareKind) {
    const status = getStatus(); if (!status || status.disconnected) return;
    failure(""); const choices = sharingChoices(status); if (!choices.length) return;
    const kinds = el("share-kinds"); kinds.replaceChildren();
    for (const choice of choices) {
      const label = document.createElement("label"), radio = document.createElement("input");
      radio.type = "radio"; radio.name = "share-kind"; radio.value = choice.kind; radio.checked = choice.kind === (kind || choices[0].kind);
      radio.addEventListener("change", () => choose(choice.kind));
      label.append(radio, document.createTextNode(choice.title)); kinds.append(label);
    }
    const devices = el("share-device-list"); devices.replaceChildren();
    for (const device of sharingDevices(status)) {
      const label = document.createElement("label"), box = document.createElement("input");
      box.type="checkbox"; box.name="share-recipient"; box.value=device.id;
      box.addEventListener("change", () => failure(""));
      box.checked = device.id === status.selected_device || status.devices.length === 1;
      label.append(box, document.createTextNode(device.name)); devices.append(label);
    }
    const inboxes = el<HTMLSelectElement>("share-inbox"); inboxes.replaceChildren();
    for (const space of status.spaces.filter(s => !s.own && s.kind === "inbox")) {
      const option = document.createElement("option"); option.value = space.id; option.textContent = `${space.host} - ${space.name}`; inboxes.append(option);
    }
    choose(kind && choices.some(c => c.kind === kind) ? kind : choices[0].kind); dialog.showModal();
  }
  el("share-button").addEventListener("click", () => open());
  el("sharing-shortcuts").addEventListener("click", event => {
    const button = (event.target as HTMLElement).closest<HTMLButtonElement>("button[data-share-kind]");
    if (button && !button.disabled) open(button.dataset.shareKind as ShareKind);
  });
  el("service-preset").addEventListener("change", () => {
    const [, port, name] = el<HTMLSelectElement>("service-preset").value.split(":");
    input("service-port").value = port === "0" ? "" : port; input("service-name").value = name;
    const details = el("share-service-fields").querySelector("details"); if (details) details.open = port === "0";
  });
  input("service-name").value = "My web app";
  el("share-close").addEventListener("click", () => { if (!submitting) dialog.close(); });
  dialog.addEventListener("cancel", e => { if (submitting) e.preventDefault(); });
  el("share-form").addEventListener("submit", async e => {
    e.preventDefault(); if (submitting) return; failure("");
    const status = getStatus(); if (!status) return;
    const recipients = [...dialog.querySelectorAll<HTMLInputElement>('input[name="share-recipient"]:checked')].map(e => e.value);
    if (selected !== "send" && !recipients.length) { failure("Choose at least one device."); return; }
    submitting = true; confirm.disabled = true;
    try {
      if (selected === "send") {
        const space = status.spaces.find(s => s.id === el<HTMLSelectElement>("share-inbox").value && !s.own && s.kind === "inbox");
        if (!space) throw new Error("Choose a device that is receiving files.");
        dialog.close(); await send(space);
      } else if (selected === "service") {
        const kind = el<HTMLSelectElement>("service-preset").value.split(":")[0];
        const name = input("service-name").value.trim(), port = Number(input("service-port").value);
        if (!name || !Number.isInteger(port) || port < 1 || port > 65535) throw new Error("Name your service and choose a port from 1 to 65535.");
        await invoke("share_service", {name, kind, port, recipients}); dialog.close(); message("Service shared. Your selected devices can connect from Shared → Apps & services.");
      } else {
        const command = selected === "inbox" ? "receive_files" : selected === "folder" ? "share_folder" : "share_file";
        const published = await invoke<boolean>(command, {recipients, media: selected === "media"});
        if (published) { dialog.close(); message(selected === "inbox" ? "Selected devices can now send files here." : "Shared with your selected devices. They can open it now."); }
      }
      await refresh();
    } catch (error) { failure(String(error).includes("Name your service") ? String(error).replace(/^Error: /, "") : friendlyProblem(String(error))); }
    finally { submitting = false; confirm.disabled = false; }
  });
}
