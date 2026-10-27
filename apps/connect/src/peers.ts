import { el, input, notify } from "./ui";
import { loadPeers, savePeer, removePeer, type PeerScope } from "./peer-store";
interface Context {
  network: string;
  root_public_key: string;
  node_public_key: string;
  ticket: string | null;
}
let context: Context | null = null;
let locked = false;
let signature = "";
function scope(): PeerScope {
  if (!context) throw new Error("Join a network first.");
  return { network: context.network, root: context.root_public_key };
}
export function renderPeers(device: Context | null, busy: boolean) {
  context = device;
  locked = busy || !!device?.ticket;
  el<HTMLButtonElement>("save-peer").disabled = locked || !device;
  input("peer-name").disabled = locked || !device;
  try {
    const peers = device ? loadPeers(localStorage, scope()) : [];
    const next = JSON.stringify([peers, locked, input("peer-node-key").value]);
    if (signature === next) return;
    signature = next;
    el("saved-peers").replaceChildren();
    el("peer-storage-note").hidden = true;
    for (const peer of peers) {
      const card = document.createElement("div");
      card.className = "peer-card";
      if (peer.node === input("peer-node-key").value)
        card.classList.add("active");
      const avatar = document.createElement("span");
      avatar.className = "peer-avatar";
      avatar.textContent = peer.name.slice(0, 1).toUpperCase();
      avatar.setAttribute("aria-hidden", "true");
      const body = document.createElement("div");
      body.className = "peer-card-content";
      const title = document.createElement("strong");
      title.textContent = peer.name;
      const detail = document.createElement("small");
      detail.textContent = `${peer.node.slice(0, 12)}… · identity checked when connecting`;
      body.append(title, detail);
      const choose = document.createElement("button");
      choose.type = "button";
      choose.className = "secondary";
      choose.textContent =
        peer.node === input("peer-node-key").value ? "Selected" : "Choose";
      choose.disabled = locked;
      choose.addEventListener("click", () => {
        input("peer-node-key").value = peer.node;
        input("peer-name").value = peer.name;
        renderPeers(context, false);
      });
      const remove = document.createElement("button");
      remove.type = "button";
      remove.className = "remove-peer";
      remove.textContent = "Forget";
      remove.setAttribute(
        "aria-label",
        `Forget saved reference to ${peer.name}`,
      );
      remove.disabled = locked;
      remove.addEventListener("click", () => {
        try {
          removePeer(localStorage, scope(), peer.node);
          signature = "";
          renderPeers(context, false);
          notify(
            "Saved reference removed. Authority permissions are unchanged.",
          );
        } catch {
          notify(
            "Device references could not be saved. Check local storage availability.",
          );
        }
      });
      card.append(avatar, body, choose, remove);
      el("saved-peers").append(card);
    }
  } catch {
    el("saved-peers").replaceChildren();
    el("peer-storage-note").hidden = false;
    el("peer-storage-note").textContent =
      "Saved references are unavailable. You can still enter and verify a public key directly.";
  }
}
el("save-peer").addEventListener("click", () => {
  if (locked || !context) return;
  try {
    savePeer(
      localStorage,
      scope(),
      {
        name: input("peer-name").value.trim(),
        node: input("peer-node-key").value.trim(),
      },
      context.node_public_key,
    );
    signature = "";
    renderPeers(context, false);
    notify("Device reference saved for this pinned network.");
  } catch (error) {
    notify(
      error instanceof Error
        ? error.message
        : "The device reference could not be saved.",
    );
  }
});
input("peer-node-key").addEventListener("input", () =>
  renderPeers(context, locked),
);
