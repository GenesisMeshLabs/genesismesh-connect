import { invoke } from "@tauri-apps/api/core";
import { el, input } from "./ui";
import { friendlyProblem, type HomeStatus, type HomeSpace } from "./home-state";
import { sharingChoices, sharingDevices, receivingChoices, type ShareKind } from "./sharing-state";
export function setupSharing(getStatus: () => HomeStatus | null, refresh: () => Promise<void>, message: (s: string) => void, send: (space: HomeSpace) => Promise<void>) {
  const dialog = el<HTMLDialogElement>("share-dialog"), confirm = el<HTMLButtonElement>("share-confirm");
  let submitting = false, selected: ShareKind = "file";
  const failure = (s: string) => { el("share-problem").textContent = s; el("share-problem").hidden = !s; };
  const captions = {service:"Share service",file:"Choose file and share",media:"Choose photos & videos",folder:"Choose folder and share",inbox:"Start receiving here",send:"Choose file and send"};
  function targets() {
    const select=el<HTMLSelectElement>("share-inbox"), previous=select.value;
    select.replaceChildren();
    for(const space of getStatus()?.spaces.filter(s=>!s.own&&s.kind==="inbox")||[]) select.add(new Option(space.host,space.id));
    if([...select.options].some(o=>o.value===previous)) select.value=previous;
  }
  function choose(kind: ShareKind) {
    selected=kind;failure("");const status=getStatus();if(!status)return;
    el("share-title").textContent=kind==="inbox"?"Receive files on this device":kind==="send"?"Send files to another device":"What would you like to share?";
    el("share-intro").textContent=kind==="inbox"?"Choose who can send files to this device.":kind==="send"?"Choose where to send a copy. Your original file stays here.":"Choose something from this device, then who can use it.";
    el("share-description").textContent=(sharingChoices(status).find(c=>c.kind===kind)?.description||"")+" Keep Connect open while sharing or receiving.";
    el("share-recipients").hidden=kind==="send";
    el("share-recipients-title").textContent=kind==="inbox"?"Who can send files here?":"Who can access it?";
    el("share-inbox").hidden=el("share-inbox-label").hidden=kind!=="send";
    el<HTMLSelectElement>("share-inbox").disabled=kind!=="send";
    el("share-refresh-targets").hidden=kind!=="send";
    el("share-receive-fields").hidden=kind!=="inbox";
    el("receive-location-label").hidden=el("receive-location").hidden=!status.can_share_folder;
    el("receive-mobile-location").hidden=!!status.can_share_folder;
    el<HTMLSelectElement>("receive-location").disabled=kind!=="inbox"||!status.can_share_folder;
    if(kind==="inbox")el("share-description").textContent="Keep Connect open on both devices while files are sent.";
    el("share-service-fields").hidden=kind!=="service";
    for(const field of el("share-service-fields").querySelectorAll<HTMLInputElement|HTMLSelectElement>("input,select")) field.disabled=kind!=="service";
    const waiting=kind==="send"&&!el<HTMLSelectElement>("share-inbox").options.length;
    if(waiting) el("share-description").textContent="No device is ready to receive yet. On your other device, open Connect → Receive files, select this device, then tap Start receiving here. Return here and refresh receiving devices.";
    confirm.textContent=waiting?"Waiting for a receiving device":captions[kind];confirm.disabled=submitting||waiting;
  }
  function open(kind?: ShareKind) {
    const status = getStatus(); if (!status || status.disconnected) return;
    failure(""); const choices = sharingChoices(status); if (!choices.length) return;
    const kinds = el("share-kinds"); kinds.replaceChildren(); kinds.hidden = kind === "inbox" || kind === "send";
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
    const locations=el<HTMLSelectElement>("receive-location");locations.replaceChildren();
    for(const option of receivingChoices(status)) locations.add(new Option(option.label,option.value));
    targets();
    choose(kind && choices.some(c => c.kind === kind) ? kind : choices[0].kind); dialog.showModal();
  }
  el("share-button").addEventListener("click", () => open());
  el("sharing-shortcuts").addEventListener("click", event => {
    const button = (event.target as HTMLElement).closest<HTMLButtonElement>("button[data-share-kind]");
    if (button && !button.disabled) open(button.dataset.shareKind as ShareKind);
  });
  el("share-refresh-targets").addEventListener("click",async()=>{
    const button=el<HTMLButtonElement>("share-refresh-targets");button.disabled=true;
    try{await invoke("check_network");await refresh();targets();choose("send");}catch(error){failure(friendlyProblem(String(error)));}
    finally{button.disabled=false;}
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
        if(selected==="media")confirm.textContent="Preparing your photos & videos…";
        const published = await invoke<boolean>(command, {recipients, media: selected === "media", ...(selected==="inbox"?{location:el<HTMLSelectElement>("receive-location").value}:{})});
        if (published) { dialog.close(); message(selected === "inbox" ? "Ready to receive. On another device, choose Send files and select this device." : "Shared with your selected devices. They can open it now."); }
      }
      await refresh();
    } catch (error) { failure(String(error).includes("Name your service") ? String(error).replace(/^Error: /, "") : friendlyProblem(String(error))); }
    finally { submitting = false; confirm.disabled = selected==="send"&&!el<HTMLSelectElement>("share-inbox").options.length; confirm.textContent=captions[selected]; }
  });
}
